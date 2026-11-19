use std::fmt;
use std::sync::Arc;

use tc_algo::Params;
use tc_asn1::NamedOid;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_x509::cert::X509Certificate;
use tc_x509::extension::key_identifier_of;

use crate::PkcsError;

// The MAC a write keeps from the file it was loaded from, as Bouncy Castle does: its digest, count
// and salt length, not the salt itself
#[derive(Clone)]
pub(crate) struct MacShape {
    pub(crate) digest: AlgorithmIdentifier,
    pub(crate) iterations: Option<usize>,
    pub(crate) salt_length: usize,
}

impl Default for MacShape {
    // HMAC-SHA1 with a salt of 20 bytes, and twice the count of the PBE, as Bouncy Castle writes
    fn default() -> Self {
        Self {
            digest: AlgorithmIdentifier::with_null(SHA1.oid()),
            iterations: None,
            salt_length: 20,
        }
    }
}

// id-sha1 of OIW
const SHA1: NamedOid = NamedOid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x1a], "1.3.14.3.2.26", "id-sha1");

// Bouncy Castle's Pkcs12Store, the entries of a PKCS#12 file: private keys under an alias with
// the certificate of each, certificates under an alias of their own, and the certificates their
// chains are built from. Aliases are compared without regard to case, as there. It holds no
// algorithms: PkcsOperator::pkcs12() loads, saves and builds chains
#[derive(Clone, Default)]
pub struct Pkcs12Store {
    pub(crate) keys: Vec<(String, Arc<dyn Params>)>,
    // The alias of a key loaded under a friendlyName, by its localKeyId in hex
    pub(crate) local_ids: Vec<(String, String)>,
    pub(crate) certs: Vec<(String, X509Certificate)>,
    pub(crate) chain_certs: Vec<([u8; 20], X509Certificate)>,
    // The certificate of a key, by the localKeyId in hex or the alias
    pub(crate) key_certs: Vec<(String, X509Certificate)>,
    pub(crate) mac: MacShape,
}

// The aliases of the entries, never the keys
impl fmt::Debug for Pkcs12Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs12Store")
            .field("aliases", &self.aliases())
            .finish_non_exhaustive()
    }
}

pub(crate) fn same_alias(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

pub(crate) fn find<K, V>(entries: &[(K, V)], matches: impl Fn(&K) -> bool) -> Option<&V> {
    entries
        .iter()
        .find(|(key, _)| matches(key))
        .map(|(_, value)| value)
}

// Adds or replaces, keeping the order of a replaced entry at the end, as Bouncy Castle's Map
pub(crate) fn map<K, V>(entries: &mut Vec<(K, V)>, key: K, value: V, matches: impl Fn(&K) -> bool) {
    entries.retain(|(existing, _)| !matches(existing));
    entries.push((key, value));
}

pub(crate) fn remove<K, V>(entries: &mut Vec<(K, V)>, matches: impl Fn(&K) -> bool) -> Option<V> {
    let at = entries.iter().position(|(key, _)| matches(key))?;
    Some(entries.remove(at).1)
}

// Bouncy Castle's CertID: the key identifier of the certificate's public key
pub(crate) fn cert_id(certificate: &X509Certificate) -> [u8; 20] {
    key_identifier_of(certificate.subject_public_key_info())
}

impl Pkcs12Store {
    pub fn new() -> Self {
        Self::default()
    }

    // The aliases of keys, then those of certificates without a key
    pub fn aliases(&self) -> Vec<&str> {
        let mut aliases: Vec<&str> = self.keys.iter().map(|(alias, _)| alias.as_str()).collect();
        for (alias, _) in &self.certs {
            if !aliases.iter().any(|known| same_alias(known, alias)) {
                aliases.push(alias);
            }
        }
        aliases
    }

    pub fn len(&self) -> usize {
        self.aliases().len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.certs.is_empty()
    }

    pub fn contains_alias(&self, alias: &str) -> bool {
        self.is_key_entry(alias) || find(&self.certs, |known| same_alias(known, alias)).is_some()
    }

    pub fn is_key_entry(&self, alias: &str) -> bool {
        find(&self.keys, |known| same_alias(known, alias)).is_some()
    }

    pub fn is_certificate_entry(&self, alias: &str) -> bool {
        !self.is_key_entry(alias) && find(&self.certs, |known| same_alias(known, alias)).is_some()
    }

    pub fn key(&self, alias: &str) -> Option<&dyn Params> {
        find(&self.keys, |known| same_alias(known, alias)).map(|key| key.as_ref())
    }

    // The certificate under the alias, or that of the key under it
    pub fn certificate(&self, alias: &str) -> Option<&X509Certificate> {
        if let Some(certificate) = find(&self.certs, |known| same_alias(known, alias)) {
            return Some(certificate);
        }
        let key_certs_key = find(&self.local_ids, |known| *known == alias)
            .map(String::as_str)
            .unwrap_or(alias);
        find(&self.key_certs, |known| same_alias(known, key_certs_key))
    }

    pub fn certificate_alias(&self, certificate: &X509Certificate) -> Option<&str> {
        self.certs
            .iter()
            .chain(&self.key_certs)
            .find(|(_, known)| known == certificate)
            .map(|(alias, _)| alias.as_str())
    }

    // The key with its chain, the certificate of the key first. An alias already in use is
    // replaced. NoCertificateChain for an empty chain, as Bouncy Castle refuses a private key
    // without one
    pub fn set_key_entry(
        &mut self,
        alias: &str,
        key: Arc<dyn Params>,
        chain: Vec<X509Certificate>,
    ) -> Result<(), PkcsError> {
        let Some(first) = chain.first() else {
            return Err(PkcsError::NoCertificateChain);
        };
        if self.is_key_entry(alias) {
            self.delete_entry(alias);
        }
        map(&mut self.keys, alias.to_string(), key, |known| {
            same_alias(known, alias)
        });
        map(&mut self.certs, alias.to_string(), first.clone(), |known| {
            same_alias(known, alias)
        });
        for certificate in chain {
            let id = cert_id(&certificate);
            map(&mut self.chain_certs, id, certificate, |known| *known == id);
        }
        Ok(())
    }

    // AliasInUse when a key has the alias
    pub fn set_certificate_entry(
        &mut self,
        alias: &str,
        certificate: X509Certificate,
    ) -> Result<(), PkcsError> {
        if self.is_key_entry(alias) {
            return Err(PkcsError::AliasInUse);
        }
        let id = cert_id(&certificate);
        map(
            &mut self.certs,
            alias.to_string(),
            certificate.clone(),
            |known| same_alias(known, alias),
        );
        map(&mut self.chain_certs, id, certificate, |known| *known == id);
        Ok(())
    }

    pub fn delete_entry(&mut self, alias: &str) {
        if let Some(certificate) = remove(&mut self.certs, |known| same_alias(known, alias)) {
            let id = cert_id(&certificate);
            remove(&mut self.chain_certs, |known| *known == id);
        }
        if remove(&mut self.keys, |known| same_alias(known, alias)).is_some() {
            let key_certs_key = remove(&mut self.local_ids, |known| *known == alias)
                .unwrap_or_else(|| alias.to_string());
            if let Some(certificate) = remove(&mut self.key_certs, |known| {
                same_alias(known, &key_certs_key)
            }) {
                let id = cert_id(&certificate);
                remove(&mut self.chain_certs, |known| *known == id);
            }
        }
    }
}
