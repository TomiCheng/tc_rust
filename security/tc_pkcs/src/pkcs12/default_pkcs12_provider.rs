use std::sync::Arc;

use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::Params;
use tc_asn1::{
    Asn1Any, Asn1BmpString, Asn1Integer, Asn1Object, Asn1OctetString, Asn1Oid, Asn1SequenceOf,
    DecodingContext, DecodingOptions, Encode, EncodingOptions, NamedOid, tag,
};
use tc_asn1_cms::content::{ContentInfo, ContentType, EncryptedContentInfo, EncryptedData};
use tc_asn1_pkcs::{
    AuthenticatedSafe, CertBag, EncryptedPrivateKeyInfo, MacData, Pfx, Pkcs5Algorithm,
    Pkcs9Attribute, Pkcs12Algorithm, PrivateKeyInfo, SafeBag,
};
use tc_asn1_x500::{Attribute, AttributeValue, DirectoryString};
use tc_asn1_x509::alg::{AlgorithmIdentifier, DigestInfo};
use tc_asn1_x509::ext::KeyPurposeId;
use tc_x509::cert::X509Certificate;
use tc_zeroize::Zeroizing;

use super::pkcs12_store::{MacShape, cert_id, find, map, same_alias};
use crate::PkcsError;
use crate::default_pkcs_operator::DefaultPkcsOperator;
use crate::der::decode_all;
use crate::operator::encrypted_private_key_info::{
    EncryptedPrivateKeyInfoProvider, PbeParams, Pbes2Params,
};
use crate::operator::private_key_info::PrivateKeyInfoProvider;
use crate::pkcs12::{Pkcs12Options, Pkcs12Provider, Pkcs12Store};

// The salt of each PBE, as Bouncy Castle writes it
const SALT_SIZE: usize = 20;

// The fewest bytes of MAC salt a write keeps from a loaded file
const MIN_MAC_SALT_LENGTH: usize = 8;

// The largest iteration count a load accepts, so that a file cannot make it run for ever
const MAX_ITERATIONS: usize = 5_000_000;

// id_oracle_pkcs12_trusted_key_usage
const ORACLE_TRUSTED_KEY_USAGE: NamedOid = NamedOid::new(
    &[
        0x60, 0x86, 0x48, 0x01, 0x86, 0xf9, 0x66, 0xad, 0xca, 0x7b, 0x01, 0x01,
    ],
    "2.16.840.1.113894.746875.1.1",
    "id-oracle-pkcs12-trusted-key-usage",
);

impl Pkcs12Provider for DefaultPkcsOperator {
    fn load(&self, der: &[u8], password: Option<&str>) -> Result<Pkcs12Store, PkcsError> {
        let pfx: Pfx = decode_all(der)?;
        let info = pfx.auth_safe();
        let mut store = Pkcs12Store::new();

        if let Some(mac_data) = pfx.mac_data() {
            let password = password.ok_or(PkcsError::MissingPassword)?;
            let iterations = iterations(mac_data.iterations())?;
            let data = content_octets(info)?;
            let mac = mac_data.mac();
            let salt = mac_data.mac_salt().as_bytes();
            if !self.verify_mac(
                mac.digest_algorithm(),
                salt,
                iterations,
                password,
                &data,
                mac.digest(),
            )? {
                return Err(PkcsError::InvalidMac);
            }
            store.mac = MacShape {
                digest: mac.digest_algorithm().clone(),
                iterations: Some(iterations),
                salt_length: salt.len().max(MIN_MAC_SALT_LENGTH),
            };
        }

        let mut unmarked: Option<Arc<dyn Params>> = None;
        let mut cert_bags = Vec::new();
        if ContentType::DATA == *info.content_type() {
            let auth_safe: AuthenticatedSafe = decode_all(&content_octets(info)?)?;
            for content in auth_safe.content_infos() {
                let octets = if ContentType::DATA == *content.content_type() {
                    Zeroizing::new(content_octets(content)?)
                } else if ContentType::ENCRYPTED_DATA == *content.content_type() {
                    let password = password.ok_or(PkcsError::MissingPassword)?;
                    let data: EncryptedData = decode_all(content_of(content)?.raw())?;
                    let encrypted = data.encrypted_content_info();
                    let sealed = encrypted
                        .encrypted_content()
                        .ok_or(PkcsError::InvalidStore)?;
                    self.encrypted_private_key_info.decrypt_bytes(
                        password,
                        &EncryptedPrivateKeyInfo::new(
                            encrypted.content_encryption_algorithm().clone(),
                            sealed.clone(),
                        ),
                    )?
                } else {
                    continue;
                };
                let bags: Asn1SequenceOf<SafeBag> = decode_all(&octets)?;
                for bag in bags.into_elements() {
                    if Pkcs12Algorithm::CERT_BAG == *bag.bag_id() {
                        cert_bags.push(bag);
                    } else if Pkcs12Algorithm::KEY_BAG == *bag.bag_id() {
                        let info: PrivateKeyInfo = decode_all(bag.bag_value().raw())?;
                        self.load_key(&mut store, &info, &bag, &mut unmarked)?;
                    } else if Pkcs12Algorithm::PKCS8_SHROUDED_KEY_BAG == *bag.bag_id() {
                        let password = password.ok_or(PkcsError::MissingPassword)?;
                        let sealed: EncryptedPrivateKeyInfo = decode_all(bag.bag_value().raw())?;
                        let info = self.encrypted_private_key_info.decrypt(password, &sealed)?;
                        self.load_key(&mut store, &info, &bag, &mut unmarked)?;
                    }
                }
            }
        }

        for bag in cert_bags {
            let cert_bag: CertBag = decode_all(bag.bag_value().raw())?;
            if Pkcs9Attribute::X509_CERTIFICATE != *cert_bag.cert_id() {
                return Err(PkcsError::InvalidStore);
            }
            let value: Asn1OctetString = decode_all(cert_bag.cert_value().raw())?;
            let certificate = X509Certificate::decode(value.as_bytes())?;
            let (alias, local_id) = names(&bag)?;

            let id = cert_id(&certificate);
            map(&mut store.chain_certs, id, certificate.clone(), |known| {
                *known == id
            });
            if let Some(key) = unmarked.take() {
                if store.key_certs.is_empty() {
                    let name = hex(&id);
                    store.key_certs.push((name.clone(), certificate));
                    map(&mut store.keys, name.clone(), key, |known| {
                        same_alias(known, &name)
                    });
                } else {
                    unmarked = Some(key);
                }
            } else {
                if let Some(local_id) = local_id {
                    let name = hex(&local_id);
                    map(
                        &mut store.key_certs,
                        name.clone(),
                        certificate.clone(),
                        |known| same_alias(known, &name),
                    );
                }
                if let Some(alias) = alias {
                    map(&mut store.certs, alias.clone(), certificate, |known| {
                        same_alias(known, &alias)
                    });
                }
            }
        }
        if let Some(key) = unmarked {
            map(&mut store.keys, "unmarked".to_string(), key, |known| {
                same_alias(known, "unmarked")
            });
        }
        Ok(store)
    }

    fn save(
        &self,
        store: &Pkcs12Store,
        password: Option<&str>,
        options: &Pkcs12Options,
    ) -> Result<Vec<u8>, PkcsError> {
        let iterations = options.iterations();

        let mut key_bags = Vec::new();
        for (alias, key) in &store.keys {
            let info = self.private_key_info.encode(key.as_ref())?;
            let (bag_id, value) = match (password, options.key_algorithm()) {
                (Some(password), Some(algorithm)) => {
                    let (oid, params) =
                        self.scheme(algorithm, options.key_prf(), password, iterations)?;
                    let sealed = self.encrypted_private_key_info.encrypt_by_oid(
                        &oid,
                        params.as_ref(),
                        &info,
                    )?;
                    (Pkcs12Algorithm::PKCS8_SHROUDED_KEY_BAG.oid(), any(&sealed)?)
                }
                _ => (Pkcs12Algorithm::KEY_BAG.oid(), any(&info)?),
            };
            let mut attributes = vec![friendly_name(alias)?];
            if let Some(certificate) = store.certificate(alias) {
                attributes.push(local_key_id(certificate)?);
            }
            key_bags.push(SafeBag::new(bag_id, value).with_bag_attributes(attributes));
        }
        let keys_der =
            Zeroizing::new(Asn1SequenceOf::new(key_bags).encode_to_vec(&EncodingOptions::DER)?);
        let keys_info = data(&keys_der);

        let mut cert_bags = Vec::new();
        let mut done: Vec<&X509Certificate> = Vec::new();
        for (alias, _) in &store.keys {
            let Some(certificate) = store.certificate(alias) else {
                continue;
            };
            let attributes = vec![friendly_name(alias)?, local_key_id(certificate)?];
            cert_bags.push(cert_bag(certificate)?.with_bag_attributes(attributes));
            done.push(certificate);
        }
        for (alias, certificate) in &store.certs {
            if store.is_key_entry(alias) {
                continue;
            }
            let mut attributes = vec![friendly_name(alias)?];
            if options.oracle_trusted_key_usage() {
                attributes.push(trusted_key_usage(certificate)?);
            }
            cert_bags.push(cert_bag(certificate)?.with_bag_attributes(attributes));
            done.push(certificate);
        }
        for (_, certificate) in &store.chain_certs {
            if done.contains(&certificate) {
                continue;
            }
            cert_bags.push(cert_bag(certificate)?);
        }
        let certs_der = Asn1SequenceOf::new(cert_bags).encode_to_vec(&EncodingOptions::DER)?;
        let certs_info = match (password, options.cert_algorithm()) {
            (Some(password), Some(algorithm)) => {
                let (oid, params) =
                    self.scheme(algorithm, options.cert_prf(), password, iterations)?;
                let sealed = self.encrypted_private_key_info.encrypt_bytes_by_oid(
                    &oid,
                    params.as_ref(),
                    &certs_der,
                )?;
                let encrypted = EncryptedData::new(
                    EncryptedContentInfo::new(
                        ContentType::DATA.oid(),
                        sealed.encryption_algorithm().clone(),
                    )
                    .with_encrypted_content(sealed.encrypted_data().clone()),
                );
                ContentInfo::new(ContentType::ENCRYPTED_DATA.oid()).with_content(any(&encrypted)?)
            }
            _ => data(&certs_der),
        };

        let auth_safe = AuthenticatedSafe::new(vec![keys_info, certs_info])
            .encode_to_vec(&EncodingOptions::DER)?;
        let mut pfx = Pfx::new(data(&auth_safe));
        if let Some(password) = password {
            let shape = &store.mac;
            let mac_iterations = shape.iterations.unwrap_or(2 * iterations);
            let salt = random(shape.salt_length);
            let mac =
                self.calculate_mac(&shape.digest, &salt, mac_iterations, password, &auth_safe)?;
            pfx = pfx.with_mac_data(
                MacData::new(
                    DigestInfo::new(shape.digest.clone(), &mac),
                    Asn1OctetString::new(&salt),
                )
                .with_iterations((mac_iterations as u64).into()),
            );
        }
        Ok(pfx.encode_to_vec(&EncodingOptions::DER)?)
    }

    fn certificate_chain(&self, store: &Pkcs12Store, alias: &str) -> Option<Vec<X509Certificate>> {
        if !store.is_key_entry(alias) {
            return None;
        }
        let mut current = store.certificate(alias)?.clone();
        let mut chain: Vec<X509Certificate> = Vec::new();
        loop {
            let next = self.issuer_of(store, &current);
            if chain.contains(&current) {
                break;
            }
            chain.push(current.clone());
            match next {
                Some(next) if next != current => current = next,
                _ => break,
            }
        }
        Some(chain)
    }
}

impl DefaultPkcsOperator {
    // As Bouncy Castle's LoadKeyBag: a key under its friendlyName, paired with its certificate by
    // localKeyId, and a key with neither marked to take the first certificate
    fn load_key(
        &self,
        store: &mut Pkcs12Store,
        info: &PrivateKeyInfo,
        bag: &SafeBag,
        unmarked: &mut Option<Arc<dyn Params>>,
    ) -> Result<(), PkcsError> {
        let key: Arc<dyn Params> = Arc::from(self.private_key_info.decode(info)?);
        let (alias, local_id) = names(bag)?;
        if let Some(alias) = &alias {
            map(&mut store.keys, alias.clone(), key.clone(), |known| {
                same_alias(known, alias)
            });
        }
        match local_id {
            Some(local_id) => {
                let name = hex(&local_id);
                match alias {
                    None => map(&mut store.keys, name.clone(), key, |known| {
                        same_alias(known, &name)
                    }),
                    Some(alias) => map(&mut store.local_ids, alias.clone(), name, |known| {
                        *known == alias
                    }),
                }
            }
            None => *unmarked = Some(key),
        }
        Ok(())
    }

    // The scheme and its params: a PBE scheme of PKCS#12 by its OID, or PBES2 over the cipher
    // with an IV of one block when a PRF is given
    fn scheme(
        &self,
        algorithm: &Asn1Oid,
        prf: Option<&Asn1Oid>,
        password: &str,
        iterations: usize,
    ) -> Result<(Asn1Oid, Box<dyn Params>), PkcsError> {
        let salt = random(SALT_SIZE);
        Ok(match prf {
            Some(prf) => {
                let block = self.algo.cipher().get_by_oid(algorithm)?.block_size();
                let params = Pbes2Params::new(
                    password,
                    salt,
                    iterations,
                    prf.clone(),
                    algorithm.clone(),
                    random(block),
                );
                (Pkcs5Algorithm::PBES2.oid(), Box::new(params))
            }
            None => (
                algorithm.clone(),
                Box::new(PbeParams::new(password, salt, iterations)),
            ),
        })
    }

    // HMAC under a key the PKCS#12 KDF derives from the password, the PBEwithHmac row of
    // tc_algo by the OID of the digest, as Bouncy Castle's CalculatePbeMac
    fn calculate_mac(
        &self,
        digest: &AlgorithmIdentifier,
        salt: &[u8],
        iterations: usize,
        password: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, PkcsError> {
        let pbe = self.algo.pbe().get_by_oid(digest.algorithm())?;
        let key = pbe.generate_params(password, salt, iterations)?;
        Ok(self
            .algo
            .mac()
            .calculate_by_name(pbe.target(), key.as_ref(), data)?)
    }

    fn verify_mac(
        &self,
        digest: &AlgorithmIdentifier,
        salt: &[u8],
        iterations: usize,
        password: &str,
        data: &[u8],
        tag: &[u8],
    ) -> Result<bool, PkcsError> {
        let pbe = self.algo.pbe().get_by_oid(digest.algorithm())?;
        let key = pbe.generate_params(password, salt, iterations)?;
        Ok(self
            .algo
            .mac()
            .verify_by_name(pbe.target(), key.as_ref(), data, tag)?)
    }

    // The next certificate of a chain: the one whose key identifier the authority key identifier
    // names, or else one of the issuer's name whose key verifies the signature
    fn issuer_of(
        &self,
        store: &Pkcs12Store,
        certificate: &X509Certificate,
    ) -> Option<X509Certificate> {
        let mut context = DecodingContext::new(DecodingOptions::default());
        let by_key_id = certificate
            .extensions()
            .and_then(|extensions| {
                extensions
                    .get_authority_key_identifier(&mut context)
                    .ok()
                    .flatten()
            })
            .and_then(|aki| <[u8; 20]>::try_from(aki.key_identifier()?).ok())
            .and_then(|id| find(&store.chain_certs, |known| *known == id).cloned());
        if by_key_id.is_some() {
            return by_key_id;
        }
        let issuer = certificate.issuer();
        if issuer.equivalent(certificate.subject()) {
            return None;
        }
        store
            .chain_certs
            .iter()
            .map(|(_, candidate)| candidate)
            .find(|candidate| {
                candidate.subject().equivalent(issuer) && self.verifies(certificate, candidate)
            })
            .cloned()
    }

    fn verifies(&self, certificate: &X509Certificate, issuer: &X509Certificate) -> bool {
        let Ok(key) = self.x509.spki().decode(issuer.subject_public_key_info()) else {
            return false;
        };
        let provider = self.x509.verifier_factory_provider(Arc::from(key));
        certificate
            .is_signature_valid(provider.as_ref())
            .unwrap_or(false)
    }
}

// The friendlyName and localKeyId of a bag, the first value of each
fn names(bag: &SafeBag) -> Result<(Option<String>, Option<Vec<u8>>), PkcsError> {
    let mut alias = None;
    let mut local_id = None;
    for attribute in bag.bag_attributes().unwrap_or_default() {
        let Some(value) = attribute.values().first() else {
            continue;
        };
        if Pkcs9Attribute::FRIENDLY_NAME == *attribute.attribute_type() {
            let AttributeValue::DirectoryString(DirectoryString::BmpString(name)) = value else {
                return Err(PkcsError::InvalidStore);
            };
            alias.get_or_insert_with(|| name.as_str().to_string());
        } else if Pkcs9Attribute::LOCAL_KEY_ID == *attribute.attribute_type() {
            let AttributeValue::Other(Asn1Object::OctetString(id)) = value else {
                return Err(PkcsError::InvalidStore);
            };
            local_id.get_or_insert_with(|| id.as_bytes().to_vec());
        }
    }
    Ok((alias, local_id))
}

fn friendly_name(alias: &str) -> Result<Attribute, PkcsError> {
    let name = DirectoryString::BmpString(Asn1BmpString::new(alias)?);
    Ok(Attribute::new(
        Pkcs9Attribute::FRIENDLY_NAME.oid(),
        vec![AttributeValue::DirectoryString(name)],
    )?)
}

fn local_key_id(certificate: &X509Certificate) -> Result<Attribute, PkcsError> {
    let id = Asn1OctetString::new(&cert_id(certificate));
    Ok(Attribute::new(
        Pkcs9Attribute::LOCAL_KEY_ID.oid(),
        vec![AttributeValue::Other(Asn1Object::OctetString(id))],
    )?)
}

// The purposes of the certificate's extended key usage, or anyExtendedKeyUsage without one
fn trusted_key_usage(certificate: &X509Certificate) -> Result<Attribute, PkcsError> {
    let mut context = DecodingContext::new(DecodingOptions::default());
    let purposes = match certificate.extensions() {
        Some(extensions) => extensions
            .get_extended_key_usage(&mut context)?
            .map(|usage| usage.purposes().to_vec()),
        None => None,
    }
    .unwrap_or_else(|| vec![KeyPurposeId::ANY_EXTENDED_KEY_USAGE.oid()]);
    Ok(Attribute::new(
        ORACLE_TRUSTED_KEY_USAGE.oid(),
        purposes
            .into_iter()
            .map(|oid| AttributeValue::Other(Asn1Object::Oid(oid)))
            .collect(),
    )?)
}

fn cert_bag(certificate: &X509Certificate) -> Result<SafeBag, PkcsError> {
    let value = Asn1Any::primitive(tag::OCTET_STRING, &certificate.encode()?);
    let bag = CertBag::new(Pkcs9Attribute::X509_CERTIFICATE.oid(), value);
    Ok(SafeBag::new(Pkcs12Algorithm::CERT_BAG.oid(), any(&bag)?))
}

fn data(octets: &[u8]) -> ContentInfo {
    ContentInfo::new(ContentType::DATA.oid())
        .with_content(Asn1Any::primitive(tag::OCTET_STRING, octets))
}

fn content_of(info: &ContentInfo) -> Result<&Asn1Any, PkcsError> {
    info.content().ok_or(PkcsError::InvalidStore)
}

// The octets of a data ContentInfo, constructed BER included
fn content_octets(info: &ContentInfo) -> Result<Vec<u8>, PkcsError> {
    let octets: Asn1OctetString = decode_all(content_of(info)?.raw())?;
    Ok(octets.as_bytes().to_vec())
}

fn any<T: Encode>(value: &T) -> Result<Asn1Any, PkcsError> {
    decode_all(&value.encode_to_vec(&EncodingOptions::DER)?)
}

fn iterations(value: &Asn1Integer) -> Result<usize, PkcsError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|&count| count <= MAX_ITERATIONS)
        .ok_or(PkcsError::InvalidStore)
}

fn random(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    UnwrapErr(SysRng).fill_bytes(&mut bytes);
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
