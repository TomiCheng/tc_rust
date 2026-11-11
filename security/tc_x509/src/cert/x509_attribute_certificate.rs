use std::io::Write;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1GeneralizedTime, Asn1Integer, Asn1Oid, Decode, DecodingOptions,
    Encode, EncodingOptions,
};
use tc_asn1_x500::Attribute;
use tc_asn1_x509::{
    alg::AlgorithmIdentifier,
    attr::{AttCertIssuer, AttributeCertificate, Holder},
    ext::Extensions,
};

use crate::X509Error;
use crate::operator::verifier::VerifierFactoryProvider;

/// BC's `X509V2AttributeCertificate`: an attribute certificate as received, with the accessors of
/// its fields. Every method is variable time, for public values only, as a certificate is.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct X509AttributeCertificate {
    certificate: AttributeCertificate,
}

impl X509AttributeCertificate {
    /// Wraps an attribute certificate already decoded or built, as BC's constructor does.
    pub fn new(certificate: AttributeCertificate) -> Self {
        Self { certificate }
    }

    /// Decodes one BER or DER attribute certificate, keeping the signed octets as received.
    /// Trailing bytes are `TrailingData`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Asn1Error> {
        let (used, certificate) = AttributeCertificate::decode(bytes, &DecodingOptions::default())?;
        if used != bytes.len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(Self { certificate })
    }

    /// The DER octets, BC's `GetEncoded`. The signed octets are written as received, so that the
    /// signature stays valid.
    pub fn encode(&self) -> Result<Vec<u8>, Asn1Error> {
        self.certificate.encode_to_vec(&EncodingOptions::DER)
    }

    /// Writes [`encode`](Self::encode) to `out`. An encoding failure is
    /// `io::ErrorKind::InvalidData` carrying the [`Asn1Error`], with nothing written.
    /// Variable time, for public values only.
    pub fn encode_to<W: Write>(&self, out: &mut W) -> std::io::Result<()> {
        let encoding = self
            .encode()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        out.write_all(&encoding)
    }

    /// The ASN.1 structure, BC's `AttributeCertificate`.
    pub fn attribute_certificate(&self) -> &AttributeCertificate {
        &self.certificate
    }

    pub fn holder(&self) -> &Holder {
        self.certificate.holder()
    }

    pub fn issuer(&self) -> &AttCertIssuer {
        self.certificate.issuer()
    }

    pub fn serial_number(&self) -> &Asn1Integer {
        self.certificate.serial_number()
    }

    pub fn not_before(&self) -> &Asn1GeneralizedTime {
        self.certificate
            .attr_cert_validity_period()
            .not_before_time()
    }

    pub fn not_after(&self) -> &Asn1GeneralizedTime {
        self.certificate
            .attr_cert_validity_period()
            .not_after_time()
    }

    /// Whether `time` falls within the validity period, both ends included, as BC's `IsValid`.
    pub fn is_valid_at(&self, time: &Asn1GeneralizedTime) -> bool {
        self.not_before() <= time && time <= self.not_after()
    }

    pub fn attributes(&self) -> &[Attribute] {
        self.certificate.attributes()
    }

    /// The attribute of the type, BC's `GetAttributes(oid)`; a type appears at most once.
    pub fn attribute(&self, attribute_type: &Asn1Oid) -> Option<&Attribute> {
        self.attributes()
            .iter()
            .find(|attribute| attribute.attribute_type() == attribute_type)
    }

    pub fn issuer_unique_id(&self) -> Option<&Asn1BitString> {
        self.certificate.acinfo().issuer_unique_id()
    }

    pub fn extensions(&self) -> Option<&Extensions> {
        self.certificate.extensions()
    }

    /// The signed octets, the `acinfo` as received.
    pub fn acinfo(&self) -> &[u8] {
        self.certificate.acinfo_raw()
    }

    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        self.certificate.signature_algorithm()
    }

    /// The signature octets, BC's `GetSignature`.
    pub fn signature(&self) -> &[u8] {
        self.certificate.signature_value().as_bytes()
    }

    /// Whether the signature verifies with the attribute authority's key the provider holds, BC's
    /// `IsSignatureValid`. `AlgorithmMismatch` when the algorithm inside the signed part differs
    /// from the outer one.
    pub fn is_signature_valid(
        &self,
        provider: &dyn VerifierFactoryProvider,
    ) -> Result<bool, X509Error> {
        if self.signature_algorithm() != self.certificate.acinfo().signature() {
            return Err(X509Error::AlgorithmMismatch);
        }
        let factory = provider.create_verifier_factory(self.signature_algorithm())?;
        let mut calculator = factory.create_calculator()?;
        calculator.write_all(self.acinfo())?;
        calculator.result().is_verified(self.signature())
    }

    /// As `is_signature_valid`, with `InvalidSignature` for a signature that does not verify,
    /// BC's `Verify`.
    pub fn verify(&self, provider: &dyn VerifierFactoryProvider) -> Result<(), X509Error> {
        if self.is_signature_valid(provider)? {
            Ok(())
        } else {
            Err(X509Error::InvalidSignature)
        }
    }
}
