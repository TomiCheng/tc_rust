use std::io::{self, Read, Write};

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Decode, DecodingOptions, Encode, EncodingOptions,
};
use tc_asn1::io::Asn1Reader;
use tc_asn1_x500::Name;
use tc_asn1_x509::{
    alg::AlgorithmIdentifier,
    cert::{Certificate, SubjectPublicKeyInfo, Time, Version},
    ext::Extensions,
};

use crate::X509Error;
use crate::operator::verifier::VerifierFactoryProvider;

/// BC's `X509Certificate`: a certificate as received, with the accessors of its fields.
/// Every method is variable time, for public values only, as a certificate is.
///
#[doc = include_str!("../../docs/X509Certificate.md")]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct X509Certificate {
    certificate: Certificate,
}

impl X509Certificate {
    /// Wraps a certificate already decoded or built, as BC's constructor does.
    pub fn new(certificate: Certificate) -> Self {
        Self { certificate }
    }

    /// Decodes one BER or DER certificate, keeping the TBS octets as received. Trailing
    /// bytes are `TrailingData`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Asn1Error> {
        let (used, certificate) = Certificate::decode(bytes, &DecodingOptions::default())?;
        if used != bytes.len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(Self { certificate })
    }

    /// Reads one BER or DER certificate from `input` and nothing past it, so what follows
    /// stays in `input` for the next call; `None` when the input ends before a value
    /// starts. Read it through a `BufReader` for a file or a socket. A value that does
    /// not decode is `io::ErrorKind::InvalidData` carrying the [`Asn1Error`]; input that
    /// ends inside it is `io::ErrorKind::UnexpectedEof`. Variable time, for public
    /// values only.
    pub fn decode_from<R: Read>(input: R) -> io::Result<Option<Self>> {
        let mut reader = Asn1Reader::new(input, DecodingOptions::default());
        Ok(reader.read_value::<Certificate>()?.map(Self::new))
    }

    /// The DER octets, BC's `GetEncoded`. The TBS octets are written as received, so that
    /// the signature stays valid; a certificate received in BER keeps its TBS in BER.
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

    /// Whether the signature verifies with the issuer's key the provider holds, BC's
    /// `IsSignatureValid`. `AlgorithmMismatch` when the algorithm inside the TBS differs from
    /// the outer one.
    pub fn is_signature_valid(
        &self,
        provider: &dyn VerifierFactoryProvider,
    ) -> Result<bool, X509Error> {
        if self.signature_algorithm() != self.certificate.tbs().signature() {
            return Err(X509Error::AlgorithmMismatch);
        }
        let factory = provider.create_verifier_factory(self.signature_algorithm())?;
        let mut calculator = factory.create_calculator()?;
        calculator.write_all(self.tbs_certificate())?;
        calculator.result().is_verified(self.signature())
    }

    /// As `is_signature_valid`, with `InvalidSignature` for a signature that does not
    /// verify, BC's `Verify`.
    pub fn verify(&self, provider: &dyn VerifierFactoryProvider) -> Result<(), X509Error> {
        if self.is_signature_valid(provider)? {
            Ok(())
        } else {
            Err(X509Error::InvalidSignature)
        }
    }
}
