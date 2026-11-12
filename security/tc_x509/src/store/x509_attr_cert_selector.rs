use tc_asn1::{Asn1GeneralizedTime, Asn1Integer};
use tc_asn1_x500::Name;
use tc_asn1_x509::attr::AttCertIssuer;
use tc_asn1_x509::name::GeneralName;

use crate::cert::X509AttributeCertificate;

/// Selects attribute certificates by the criteria set on it, BC's `X509AttrCertStoreSelector`;
/// a criterion not set selects every attribute certificate. Use it with an iterator:
/// `certs.iter().filter(|c| selector.matches(c))`.
///
/// The issuer is matched against the directory names the issuer field carries, in its v1 or
/// v2 form, by equivalence, where BC compares the whole field.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1GeneralizedTime, Asn1Integer};
/// use tc_x509::cert::X509AttributeCertificate;
/// use tc_x509::store::X509AttrCertSelector;
///
/// # fn attribute_certificates() -> Vec<X509AttributeCertificate> { Vec::new() }
/// let certs: Vec<X509AttributeCertificate> = attribute_certificates();
///
/// // The attribute certificate of an authority with a serial number, valid at a time
/// let selector = X509AttrCertSelector::new()
///     .with_issuer("CN=Attribute Authority".parse()?)
///     .with_serial_number(Asn1Integer::from(42))
///     .with_valid_at(Asn1GeneralizedTime::new(2026, 11, 12, 0, 0, 0)?);
/// let found = certs.iter().find(|c| selector.matches(c));
/// # assert!(found.is_none());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct X509AttrCertSelector {
    serial_number: Option<Asn1Integer>,
    issuer: Option<Name>,
    valid_at: Option<Asn1GeneralizedTime>,
}

impl X509AttrCertSelector {
    /// A selector of every attribute certificate. Constant time.
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects the attribute certificate with this serial number. Constant time.
    pub fn with_serial_number(mut self, serial_number: Asn1Integer) -> Self {
        self.serial_number = Some(serial_number);
        self
    }

    /// Selects the attribute certificates whose issuer field names this directory name.
    /// Constant time.
    pub fn with_issuer(mut self, issuer: Name) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Selects the attribute certificates valid at `time`, both ends included. Constant time.
    pub fn with_valid_at(mut self, time: Asn1GeneralizedTime) -> Self {
        self.valid_at = Some(time);
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

    /// The time the attribute certificates must be valid at, if set. Constant time.
    pub fn valid_at(&self) -> Option<&Asn1GeneralizedTime> {
        self.valid_at.as_ref()
    }

    /// Whether `certificate` meets every criterion set. Variable time, for public values only.
    pub fn matches(&self, certificate: &X509AttributeCertificate) -> bool {
        self.serial_number
            .as_ref()
            .is_none_or(|serial| serial == certificate.serial_number())
            && self
                .issuer
                .as_ref()
                .is_none_or(|issuer| names_issuer(certificate.issuer(), issuer))
            && self
                .valid_at
                .as_ref()
                .is_none_or(|time| certificate.is_valid_at(time))
    }
}

// Whether the issuer field carries a directory name equivalent to `issuer`
fn names_issuer(field: &AttCertIssuer, issuer: &Name) -> bool {
    let names = match field {
        AttCertIssuer::V1Form(names) => Some(names),
        AttCertIssuer::V2Form(form) => form.issuer_name(),
        _ => None,
    };
    names.is_some_and(|names| {
        names.names().iter().any(|name| match name {
            GeneralName::DirectoryName(name) => name.equivalent(issuer),
            _ => false,
        })
    })
}
