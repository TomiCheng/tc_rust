use crate::cert::X509Certificate;
use crate::crl::{X509Crl, X509CrlEntry};

/// CRLs of any number of issuers, to tell whether a certificate is revoked by any of them.
///
/// Each CRL answers as [`X509Crl::is_revoked`] does: one of another issuer is passed over after
/// a comparison of names, and one that applies looks the certificate up in its own index of
/// serial numbers, built on its first lookup. The signature of every CRL is the caller's to
/// verify with the key of its issuer before adding it. A delta CRL is read on its own, not
/// merged with its base CRL.
#[derive(Clone, Debug, Default)]
pub struct X509CrlStore {
    crls: Vec<X509Crl>,
}

impl X509CrlStore {
    /// A store of `crls`. Constant time.
    pub fn new(crls: Vec<X509Crl>) -> Self {
        Self { crls }
    }

    /// Adds a CRL. Constant time, amortized.
    pub fn add(&mut self, crl: X509Crl) {
        self.crls.push(crl);
    }

    /// Every CRL in the store, in the order added. Constant time.
    pub fn crls(&self) -> &[X509Crl] {
        &self.crls
    }

    /// The first CRL listing the certificate under its issuer and serial number, with the
    /// entry, as [`X509Crl::revoked_certificate_of`] finds it; an entry with the reason
    /// `removeFromCRL` is found too. Variable time, for public values only.
    pub fn revoked_certificate_of(
        &self,
        certificate: &X509Certificate,
    ) -> Option<(&X509Crl, X509CrlEntry<'_>)> {
        self.crls.iter().find_map(|crl| {
            crl.revoked_certificate_of(certificate)
                .map(|entry| (crl, entry))
        })
    }

    /// Whether any CRL lists the certificate as revoked, as [`X509Crl::is_revoked`] tells it.
    /// Variable time, for public values only.
    pub fn is_revoked(&self, certificate: &X509Certificate) -> bool {
        self.crls.iter().any(|crl| crl.is_revoked(certificate))
    }
}

impl FromIterator<X509Crl> for X509CrlStore {
    fn from_iter<I: IntoIterator<Item = X509Crl>>(crls: I) -> Self {
        Self::new(crls.into_iter().collect())
    }
}

impl Extend<X509Crl> for X509CrlStore {
    fn extend<I: IntoIterator<Item = X509Crl>>(&mut self, crls: I) {
        self.crls.extend(crls);
    }
}
