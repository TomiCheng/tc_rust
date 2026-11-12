use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

use super::X509CertSelector;
use super::x509_cert_selector::subject_key_identifier_of;
use crate::cert::X509Certificate;

/// Certificates to find by an [`X509CertSelector`], BC's store of certificates.
///
/// A selector with a serial number or a subject key identifier is answered through an index of
/// each, built on the first selection after the store last changed, so a store of hundreds of
/// thousands of certificates costs a hash and a few comparisons; one with neither is answered
/// by a pass over every certificate. Names are not indexed, since they match by equivalence
/// rather than by their octets.
///
/// # Examples
///
/// ```
/// use tc_x509::cert::X509Certificate;
/// use tc_x509::store::{X509CertSelector, X509CertificateStore};
///
/// let load = |name: &str| -> Result<X509Certificate, Box<dyn std::error::Error>> {
///     let path = format!("{}/tests/data/crl/{name}.der", env!("CARGO_MANIFEST_DIR"));
///     Ok(X509Certificate::decode(&std::fs::read(path)?)?)
/// };
/// let mut store: X509CertificateStore = [load("ca")?, load("good")?].into_iter().collect();
/// store.add(load("revoked")?);
///
/// // By serial number, through the index
/// let revoked = &store.certificates()[2];
/// let selector = X509CertSelector::new()
///     .with_issuer(revoked.issuer().clone())
///     .with_serial_number(revoked.serial_number().clone());
/// let found = store.find(&selector).expect("the certificate");
/// println!("found {}", found.subject());
///
/// // By issuer alone, through a pass
/// let selector = X509CertSelector::new().with_issuer(revoked.issuer().clone());
/// for certificate in store.select(&selector) {
///     println!("{}", certificate.subject());
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Default)]
pub struct X509CertificateStore {
    certificates: Vec<X509Certificate>,
    index: OnceLock<CertificateIndex>,
}

// The certificates by serial number and by subject key identifier, as positions in list order
#[derive(Clone, Default)]
struct CertificateIndex {
    by_serial: HashMap<Vec<u8>, Vec<usize>>,
    by_subject_key_identifier: HashMap<Vec<u8>, Vec<usize>>,
}

impl CertificateIndex {
    fn build(certificates: &[X509Certificate]) -> Self {
        let mut index = Self::default();
        for (position, certificate) in certificates.iter().enumerate() {
            index
                .by_serial
                .entry(certificate.serial_number().as_bytes().to_vec())
                .or_default()
                .push(position);
            if let Some(key_identifier) = subject_key_identifier_of(certificate) {
                index
                    .by_subject_key_identifier
                    .entry(key_identifier)
                    .or_default()
                    .push(position);
            }
        }
        index
    }
}

fn positions<'a>(map: &'a HashMap<Vec<u8>, Vec<usize>>, key: &[u8]) -> &'a [usize] {
    map.get(key).map_or(&[], Vec::as_slice)
}

impl X509CertificateStore {
    /// A store of `certificates`. Constant time.
    pub fn new(certificates: Vec<X509Certificate>) -> Self {
        Self {
            certificates,
            index: OnceLock::new(),
        }
    }

    /// Adds a certificate; the index is built again on the next selection. Constant time,
    /// amortized.
    pub fn add(&mut self, certificate: X509Certificate) {
        self.certificates.push(certificate);
        self.index = OnceLock::new();
    }

    /// Every certificate in the store, in the order added. Constant time.
    pub fn certificates(&self) -> &[X509Certificate] {
        &self.certificates
    }

    /// The certificates `selector` selects, in the order added. Variable time, for public
    /// values only.
    pub fn select<'a>(
        &'a self,
        selector: &'a X509CertSelector,
    ) -> impl Iterator<Item = &'a X509Certificate> + 'a {
        let candidates: Box<dyn Iterator<Item = usize> + 'a> =
            match (selector.serial_number(), selector.subject_key_identifier()) {
                (Some(serial_number), _) => Box::new(
                    positions(&self.index().by_serial, serial_number.as_bytes())
                        .iter()
                        .copied(),
                ),
                (None, Some(key_identifier)) => Box::new(
                    positions(&self.index().by_subject_key_identifier, key_identifier)
                        .iter()
                        .copied(),
                ),
                (None, None) => Box::new(0..self.certificates.len()),
            };
        candidates
            .map(move |position| &self.certificates[position])
            .filter(move |certificate| selector.matches(certificate))
    }

    /// The first certificate `selector` selects. Variable time, for public values only.
    pub fn find<'a>(&'a self, selector: &'a X509CertSelector) -> Option<&'a X509Certificate> {
        self.select(selector).next()
    }

    fn index(&self) -> &CertificateIndex {
        self.index
            .get_or_init(|| CertificateIndex::build(&self.certificates))
    }
}

impl fmt::Debug for X509CertificateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509CertificateStore")
            .field("certificates", &self.certificates.len())
            .finish_non_exhaustive()
    }
}

impl FromIterator<X509Certificate> for X509CertificateStore {
    fn from_iter<I: IntoIterator<Item = X509Certificate>>(certificates: I) -> Self {
        Self::new(certificates.into_iter().collect())
    }
}

impl Extend<X509Certificate> for X509CertificateStore {
    fn extend<I: IntoIterator<Item = X509Certificate>>(&mut self, certificates: I) {
        self.certificates.extend(certificates);
        self.index = OnceLock::new();
    }
}
