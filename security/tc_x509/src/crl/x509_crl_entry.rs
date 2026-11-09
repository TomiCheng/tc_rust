use tc_asn1::{Asn1Integer, DecodingContext, DecodingOptions};
use tc_asn1_x500::Name;
use tc_asn1_x509::{
    cert::Time,
    crl::RevokedCertificate,
    ext::{ExtensionId, Extensions},
    name::{GeneralName, GeneralNames},
};

/// BC's `X509CrlEntry`: a revoked certificate of a CRL, with the issuer of that certificate when
/// the CRL is indirect. It borrows the entry from its `X509Crl`. Every method is variable time, for
/// public values only.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct X509CrlEntry<'a> {
    entry: &'a RevokedCertificate,
    certificate_issuer: Option<Name>,
}

impl<'a> X509CrlEntry<'a> {
    pub(crate) fn new(entry: &'a RevokedCertificate, certificate_issuer: Option<Name>) -> Self {
        Self {
            entry,
            certificate_issuer,
        }
    }

    // BC's LoadCertificateIssuer: in an indirect CRL, the certificateIssuer extension of an entry
    // names the issuer of it and of the entries after it, until another entry names a new one.
    // An extension that does not decode, or names no directory name, gives none, as BC does
    pub(crate) fn load_certificate_issuer(
        entry: &RevokedCertificate,
        is_indirect: bool,
        previous: Option<Name>,
    ) -> Option<Name> {
        if !is_indirect {
            return None;
        }
        let Some(extensions) = entry.extensions() else {
            return previous;
        };
        let mut context = DecodingContext::new(DecodingOptions::default());
        match extensions.get_as::<GeneralNames>(ExtensionId::CERTIFICATE_ISSUER, &mut context) {
            Ok(None) => previous,
            Ok(Some(names)) => names.names().iter().find_map(|name| match name {
                GeneralName::DirectoryName(name) => Some(name.clone()),
                _ => None,
            }),
            Err(_) => None,
        }
    }

    /// The ASN.1 structure, BC's `CrlEntry`.
    pub fn revoked_certificate(&self) -> &'a RevokedCertificate {
        self.entry
    }

    pub fn serial_number(&self) -> &'a Asn1Integer {
        self.entry.user_certificate()
    }

    pub fn revocation_date(&self) -> Time {
        *self.entry.revocation_date()
    }

    /// The issuer of the revoked certificate, BC's `GetCertificateIssuer`: only for an indirect
    /// CRL, and `None` for an entry of the CRL's own issuer.
    pub fn certificate_issuer(&self) -> Option<&Name> {
        self.certificate_issuer.as_ref()
    }

    pub fn extensions(&self) -> Option<&'a Extensions> {
        self.entry.extensions()
    }
}
