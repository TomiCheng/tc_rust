use tc_asn1::{Asn1Integer, DecodingContext, DecodingOptions};
use tc_asn1_x500::Name;
use tc_asn1_x509::cert::Time;

use crate::cert::X509Certificate;

/// Selects certificates by the criteria set on it, BC's `X509CertStoreSelector`; a
/// criterion not set selects every certificate. Use it with an iterator:
/// `certs.iter().filter(|c| selector.matches(c))`.
///
/// Names are compared as RFC 5280 matches them, a key identifier as its octets; a
/// certificate whose extension does not decode is not selected by it.
#[derive(Clone, Debug, Default)]
pub struct X509CertSelector {
    serial_number: Option<Asn1Integer>,
    issuer: Option<Name>,
    subject: Option<Name>,
    valid_at: Option<Time>,
    subject_key_identifier: Option<Vec<u8>>,
    authority_key_identifier: Option<Vec<u8>>,
}

impl X509CertSelector {
    /// A selector of every certificate. Constant time.
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects the certificate with this serial number. Constant time.
    pub fn with_serial_number(mut self, serial_number: Asn1Integer) -> Self {
        self.serial_number = Some(serial_number);
        self
    }

    /// Selects the certificates this issuer issued. Constant time.
    pub fn with_issuer(mut self, issuer: Name) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Selects the certificates of this subject. Constant time.
    pub fn with_subject(mut self, subject: Name) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Selects the certificates valid at `time`, both ends included. Constant time.
    pub fn with_valid_at(mut self, time: Time) -> Self {
        self.valid_at = Some(time);
        self
    }

    /// Selects the certificates whose subject key identifier is these octets.
    /// Constant time.
    pub fn with_subject_key_identifier(mut self, key_identifier: impl Into<Vec<u8>>) -> Self {
        self.subject_key_identifier = Some(key_identifier.into());
        self
    }

    /// Selects the certificates whose authority key identifier carries these octets as
    /// its key identifier. Constant time.
    pub fn with_authority_key_identifier(mut self, key_identifier: impl Into<Vec<u8>>) -> Self {
        self.authority_key_identifier = Some(key_identifier.into());
        self
    }

    /// The serial number to select, if set. Constant time.
    pub fn serial_number(&self) -> Option<&Asn1Integer> {
        self.serial_number.as_ref()
    }

    /// The issuer to select, if set. Constant time.
    pub fn issuer(&self) -> Option<&Name> {
        self.issuer.as_ref()
    }

    /// The subject to select, if set. Constant time.
    pub fn subject(&self) -> Option<&Name> {
        self.subject.as_ref()
    }

    /// The time the certificates must be valid at, if set. Constant time.
    pub fn valid_at(&self) -> Option<Time> {
        self.valid_at
    }

    /// The subject key identifier to select, if set. Constant time.
    pub fn subject_key_identifier(&self) -> Option<&[u8]> {
        self.subject_key_identifier.as_deref()
    }

    /// The authority key identifier to select, if set. Constant time.
    pub fn authority_key_identifier(&self) -> Option<&[u8]> {
        self.authority_key_identifier.as_deref()
    }

    fn matches_subject_key_identifier(&self, certificate: &X509Certificate) -> bool {
        let Some(wanted) = &self.subject_key_identifier else {
            return true;
        };
        subject_key_identifier_of(certificate).is_some_and(|found| found == *wanted)
    }

    fn matches_authority_key_identifier(&self, certificate: &X509Certificate) -> bool {
        let Some(wanted) = &self.authority_key_identifier else {
            return true;
        };
        let mut context = DecodingContext::new(DecodingOptions::default());
        certificate
            .extensions()
            .and_then(|extensions| {
                extensions
                    .get_authority_key_identifier(&mut context)
                    .ok()
                    .flatten()
            })
            .is_some_and(|found| found.key_identifier() == Some(wanted.as_slice()))
    }
}

impl X509CertSelector {
    /// Whether `certificate` meets every criterion set. Variable time, for public
    /// values only.
    pub fn matches(&self, certificate: &X509Certificate) -> bool {
        self.serial_number
            .as_ref()
            .is_none_or(|serial| serial == certificate.serial_number())
            && self
                .issuer
                .as_ref()
                .is_none_or(|issuer| issuer.equivalent(certificate.issuer()))
            && self
                .subject
                .as_ref()
                .is_none_or(|subject| subject.equivalent(certificate.subject()))
            && self
                .valid_at
                .as_ref()
                .is_none_or(|time| certificate.is_valid_at(time))
            && self.matches_subject_key_identifier(certificate)
            && self.matches_authority_key_identifier(certificate)
    }
}

// The key identifier of the subjectKeyIdentifier extension; none when it is absent or does not
// decode
pub(crate) fn subject_key_identifier_of(certificate: &X509Certificate) -> Option<Vec<u8>> {
    let mut context = DecodingContext::new(DecodingOptions::default());
    certificate
        .extensions()?
        .get_subject_key_identifier(&mut context)
        .ok()
        .flatten()
        .map(|found| found.key_identifier().to_vec())
}
