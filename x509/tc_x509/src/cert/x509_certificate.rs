use tc_asn1::{Asn1BitString, Asn1Error, Asn1Integer, Decode, DecodingOptions};
use tc_asn1_x500::Name;
use tc_asn1_x509::{
    alg::AlgorithmIdentifier,
    cert::{Certificate, SubjectPublicKeyInfo, Time, Version},
    ext::Extensions,
};

/// BC's `X509Certificate`: a certificate as received, with the accessors of its fields.
/// Every method is variable time, for public values only, as a certificate is.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct X509Certificate {
    certificate: Certificate,
}

impl X509Certificate {
    /// Decodes one BER or DER certificate, keeping the TBS octets as received. Trailing
    /// bytes are `TrailingData`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Asn1Error> {
        let (used, certificate) = Certificate::decode(bytes, &DecodingOptions::default())?;
        if used != bytes.len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(Self { certificate })
    }

    /// The ASN.1 structure, BC's `CertificateStructure`.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    pub fn version(&self) -> Version {
        self.certificate.tbs().version()
    }

    pub fn serial_number(&self) -> &Asn1Integer {
        self.certificate.serial_number()
    }

    pub fn issuer(&self) -> &Name {
        self.certificate.issuer()
    }

    pub fn subject(&self) -> &Name {
        self.certificate.subject()
    }

    pub fn not_before(&self) -> Time {
        self.certificate.validity().not_before()
    }

    pub fn not_after(&self) -> Time {
        self.certificate.validity().not_after()
    }

    /// Whether `time` falls within the validity period, both ends included, as BC's
    /// `IsValid`.
    pub fn is_valid_at(&self, time: &Time) -> bool {
        self.not_before() <= *time && *time <= self.not_after()
    }

    /// The signed octets, BC's `GetTbsCertificate`.
    pub fn tbs_certificate(&self) -> &[u8] {
        self.certificate.tbs_raw()
    }

    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        self.certificate.signature_algorithm()
    }

    /// The signature octets, BC's `GetSignature`.
    pub fn signature(&self) -> &[u8] {
        self.certificate.signature_value().as_bytes()
    }

    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        self.certificate.subject_public_key_info()
    }

    pub fn issuer_unique_id(&self) -> Option<&Asn1BitString> {
        self.certificate.tbs().issuer_unique_id()
    }

    pub fn subject_unique_id(&self) -> Option<&Asn1BitString> {
        self.certificate.tbs().subject_unique_id()
    }

    pub fn extensions(&self) -> Option<&Extensions> {
        self.certificate.extensions()
    }
}
