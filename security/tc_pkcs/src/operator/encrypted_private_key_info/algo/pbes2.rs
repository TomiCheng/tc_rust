use std::mem;

use tc_algo::params::cipher::{KeyWithIvOwned, ParamsWithIvOwned, Rc2ParamsOwned};
use tc_algo::params::kdf::PbeParamsOwned;
use tc_algo::{Algo, Params};
use tc_asn1::{Asn1Object, Asn1OctetString, Asn1Oid, NamedOid};
use tc_asn1_pkcs::{
    EncryptedPrivateKeyInfo, Pbes2Params as Pbes2Parameter, Pbkdf2Params, Pkcs5Algorithm,
    Rc2CbcParameter,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_zeroize::Zeroizing;

use super::{rc2_cbc, to_usize};
use crate::der::{reparse, to_object};
use crate::operator::encrypted_private_key_info::{EncryptedPrivateKeyInfoEntry, Pbes2Params};
use crate::{DefaultPkcsOperatorContext, PkcsError};

// The PRFs of PBKDF2 in RFC 8018, by the KDF row of tc_algo that runs each
const PRFS: &[(NamedOid, &str)] = &[
    (Pkcs5Algorithm::HMAC_WITH_SHA1, "PBKDF2-HMAC-SHA1"),
    (Pkcs5Algorithm::HMAC_WITH_SHA224, "PBKDF2-HMAC-SHA224"),
    (Pkcs5Algorithm::HMAC_WITH_SHA256, "PBKDF2-HMAC-SHA256"),
    (Pkcs5Algorithm::HMAC_WITH_SHA384, "PBKDF2-HMAC-SHA384"),
    (Pkcs5Algorithm::HMAC_WITH_SHA512, "PBKDF2-HMAC-SHA512"),
    (
        Pkcs5Algorithm::HMAC_WITH_SHA512_224,
        "PBKDF2-HMAC-SHA512/224",
    ),
    (
        Pkcs5Algorithm::HMAC_WITH_SHA512_256,
        "PBKDF2-HMAC-SHA512/256",
    ),
];

// The ciphers of the encryption scheme, by the length of their key when PBKDF2 writes none, as
// Bouncy Castle's GeneratorUtilities.GetDefaultKeySize gives it. The cipher itself is the row of
// algo.cipher() by the same OID
const CIPHERS: &[(&str, usize)] = &[
    // AES-CBC and AES-CFB of NIST
    ("2.16.840.1.101.3.4.1.2", 16),
    ("2.16.840.1.101.3.4.1.22", 24),
    ("2.16.840.1.101.3.4.1.42", 32),
    ("2.16.840.1.101.3.4.1.4", 16),
    ("2.16.840.1.101.3.4.1.24", 24),
    ("2.16.840.1.101.3.4.1.44", 32),
    // desCBC and des-EDE3-CBC
    ("1.3.14.3.2.7", 8),
    ("1.2.840.113549.3.7", 24),
    // rc2CBC
    ("1.2.840.113549.3.2", 16),
];

// PBES2 of RFC 8018 over PBKDF2, as Bouncy Castle's PbeUtilities takes id-PBES2. The password goes
// to PBKDF2 as UTF-8, as RFC 8018 advises and OpenSSL does; Bouncy Castle C# keeps the low byte of
// each char, so the two agree on an ASCII password only. The effective key size of RC2-CBC is read
// from its RC2-CBC-Parameter, as Bouncy Castle's CMS does, and written as the length of the key
pub(super) fn pbes2(
    _context: &DefaultPkcsOperatorContext,
) -> Vec<Box<dyn EncryptedPrivateKeyInfoEntry>> {
    vec![Box::new(Pbes2)]
}

struct Pbes2;

impl EncryptedPrivateKeyInfoEntry for Pbes2 {
    fn encrypt_by_name(
        &self,
        algo: &dyn Algo,
        name: &str,
        params: &dyn Params,
        plain: &[u8],
    ) -> Option<Result<EncryptedPrivateKeyInfo, PkcsError>> {
        let known = ["PBES2", "PKCS5SCHEME2"];
        if !known.iter().any(|known| known.eq_ignore_ascii_case(name)) {
            return None;
        }
        Some(encrypt(algo, params, plain))
    }

    fn encrypt_by_oid(
        &self,
        algo: &dyn Algo,
        oid: &Asn1Oid,
        params: &dyn Params,
        plain: &[u8],
    ) -> Option<Result<EncryptedPrivateKeyInfo, PkcsError>> {
        if Pkcs5Algorithm::PBES2 != *oid {
            return None;
        }
        Some(encrypt(algo, params, plain))
    }

    fn decrypt(
        &self,
        algo: &dyn Algo,
        password: &str,
        info: &EncryptedPrivateKeyInfo,
    ) -> Option<Result<Zeroizing<Vec<u8>>, PkcsError>> {
        let algorithm = info.encryption_algorithm();
        if Pkcs5Algorithm::PBES2 != *algorithm.algorithm() {
            return None;
        }
        Some(decrypt(
            algo,
            password,
            algorithm.parameters(),
            info.encrypted_data().as_bytes(),
        ))
    }
}

// The PRF is written with NULL parameters and the key length is left out, as Bouncy Castle's
// GenerateAlgorithmParameters writes them
fn encrypt(
    algo: &dyn Algo,
    params: &dyn Params,
    plain: &[u8],
) -> Result<EncryptedPrivateKeyInfo, PkcsError> {
    let params = params
        .as_any()
        .downcast_ref::<Pbes2Params>()
        .ok_or(PkcsError::InvalidEncryptionParams)?;
    let cipher = params.cipher();
    let key_bytes = default_key_bytes(cipher)?;
    let rc2_bits = (rc2_cbc::RC2_CBC == *cipher).then_some(key_bytes * 8);
    let key = derive(
        algo,
        kdf_name(params.prf())?,
        params.password(),
        params.salt(),
        params.iterations(),
        key_bytes,
    )?;
    let key = cipher_params(key, params.iv().to_vec(), rc2_bits);
    let sealed = algo.cipher().encrypt_by_oid(cipher, key.as_ref(), plain)?;

    let pbkdf2 = Pbkdf2Params::new(
        Asn1OctetString::new(params.salt()),
        (params.iterations() as u64).into(),
    )?
    .with_prf(AlgorithmIdentifier::with_null(params.prf().clone()));
    let scheme_parameters = match rc2_bits {
        Some(bits) => to_object(&Rc2CbcParameter::new(
            Some((rc2_cbc::parameter_version(bits) as u64).into()),
            Asn1OctetString::new(params.iv()),
        )?)?,
        None => Asn1OctetString::new(params.iv()).into(),
    };
    let pbes2 = Pbes2Parameter::new(
        AlgorithmIdentifier::with_parameters(Pkcs5Algorithm::PBKDF2.oid(), to_object(&pbkdf2)?),
        AlgorithmIdentifier::with_parameters(cipher.clone(), scheme_parameters),
    );
    Ok(EncryptedPrivateKeyInfo::new(
        AlgorithmIdentifier::with_parameters(Pkcs5Algorithm::PBES2.oid(), to_object(&pbes2)?),
        Asn1OctetString::new(&sealed),
    ))
}

// A KDF other than PBKDF2, as scrypt, or a PRF or cipher not in the tables is UnknownEncryption
fn decrypt(
    algo: &dyn Algo,
    password: &str,
    parameters: Option<&Asn1Object>,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PkcsError> {
    let pbes2: Pbes2Parameter = reparse(parameters)?;
    let kdf = pbes2.key_derivation_func();
    if Pkcs5Algorithm::PBKDF2 != *kdf.algorithm() {
        return Err(PkcsError::UnknownEncryption);
    }
    let pbkdf2: Pbkdf2Params = reparse(kdf.parameters())?;
    let scheme = pbes2.encryption_scheme();
    let cipher = scheme.algorithm();
    let default_bytes = default_key_bytes(cipher)?;
    let key_bytes = match pbkdf2.key_length() {
        Some(length) => to_usize(length)?,
        None => default_bytes,
    };
    let (iv, rc2_bits) = if rc2_cbc::RC2_CBC == *cipher {
        let parameter: Rc2CbcParameter = reparse(scheme.parameters())?;
        let bits = rc2_cbc::effective_key_bits(parameter.version())
            .ok_or(PkcsError::InvalidEncryptionParams)?;
        (parameter.iv().as_bytes().to_vec(), Some(bits))
    } else {
        match scheme.parameters() {
            Some(Asn1Object::OctetString(iv)) => (iv.as_bytes().to_vec(), None),
            _ => return Err(PkcsError::InvalidEncryptionParams),
        }
    };
    let key = derive(
        algo,
        kdf_name(pbkdf2.prf().algorithm())?,
        password,
        pbkdf2.salt().as_bytes(),
        to_usize(pbkdf2.iteration_count())?,
        key_bytes,
    )?;
    let key = cipher_params(key, iv, rc2_bits);
    Ok(Zeroizing::new(algo.cipher().decrypt_by_oid(
        cipher,
        key.as_ref(),
        sealed,
    )?))
}

fn kdf_name(prf: &Asn1Oid) -> Result<&'static str, PkcsError> {
    PRFS.iter()
        .find(|(oid, _)| *oid == *prf)
        .map(|(_, name)| *name)
        .ok_or(PkcsError::UnknownEncryption)
}

fn default_key_bytes(cipher: &Asn1Oid) -> Result<usize, PkcsError> {
    let dotted = cipher.to_string();
    CIPHERS
        .iter()
        .find(|(oid, _)| *oid == dotted)
        .map(|(_, bytes)| *bytes)
        .ok_or(PkcsError::UnknownEncryption)
}

fn derive(
    algo: &dyn Algo,
    kdf: &str,
    password: &str,
    salt: &[u8],
    iterations: usize,
    length: usize,
) -> Result<Vec<u8>, PkcsError> {
    let mut kdf = algo.kdf().get_by_name(kdf)?;
    kdf.init(&PbeParamsOwned::new(
        password.as_bytes().to_vec(),
        salt.to_vec(),
        iterations,
    ))?;
    let mut key = Zeroizing::new(vec![0; length]);
    kdf.generate_bytes(&mut key)?;
    Ok(mem::take(&mut *key))
}

fn cipher_params(key: Vec<u8>, iv: Vec<u8>, rc2_bits: Option<usize>) -> Box<dyn Params> {
    match rc2_bits {
        Some(bits) => Box::new(ParamsWithIvOwned::new(
            Rc2ParamsOwned::with_effective_key_bits(key, bits),
            iv,
        )),
        None => Box::new(KeyWithIvOwned::new(key, iv)),
    }
}
