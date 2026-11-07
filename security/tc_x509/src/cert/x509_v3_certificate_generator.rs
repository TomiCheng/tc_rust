use tc_asn1::Asn1Integer;
use tc_asn1_x500::Name;
use tc_asn1_x509::{
    cert::{SubjectPublicKeyInfo, Validity},
    ext::Extension,
};

/// BC's `X509V3CertificateGenerator`: the fields of a version 3 certificate to be signed.
/// Nothing is checked here. Every method is variable time, for public values only.
#[derive(Clone, Debug, Default)]
pub struct X509V3CertificateGenerator {
    serial_number: Option<Asn1Integer>,
    issuer: Option<Name>,
    validity: Option<Validity>,
    subject: Option<Name>,
    subject_public_key_info: Option<SubjectPublicKeyInfo>,
    extensions: Vec<Extension>,
}

impl X509V3CertificateGenerator {
    pub fn set_serial_number(&mut self, serial_number: Asn1Integer) {
        self.serial_number = Some(serial_number);
    }

    pub fn set_issuer(&mut self, issuer: Name) {
        self.issuer = Some(issuer);
    }

    pub fn set_validity(&mut self, validity: Validity) {
        self.validity = Some(validity);
    }

    pub fn set_subject(&mut self, subject: Name) {
        self.subject = Some(subject);
    }

    pub fn set_subject_public_key_info(&mut self, subject_public_key_info: SubjectPublicKeyInfo) {
        self.subject_public_key_info = Some(subject_public_key_info);
    }

    pub fn add_extension(&mut self, extension: Extension) {
        self.extensions.push(extension);
    }
}
