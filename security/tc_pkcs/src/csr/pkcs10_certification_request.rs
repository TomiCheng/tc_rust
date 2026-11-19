use std::io::Write;

use tc_algo::Params;
use tc_asn1::{Encode, EncodingOptions};
use tc_asn1_pkcs::{CertificationRequest, Pkcs9Attribute};
use tc_asn1_x500::{Attribute, AttributeValue, Name};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_asn1_x509::ext::Extensions;
use tc_x509::X509Operator;
use tc_x509::operator::verifier::VerifierFactoryProvider;

use crate::PkcsError;
use crate::der::decode_all;

// Bouncy Castle's Pkcs10CertificationRequest: a request as received, with the accessors of its
// fields. Every method is variable time, for public values only, as a request is
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Pkcs10CertificationRequest {
    request: CertificationRequest,
}

impl Pkcs10CertificationRequest {
    pub fn new(request: CertificationRequest) -> Self {
        Self { request }
    }

    // The DER or BER of a request, with nothing after it
    pub fn decode(bytes: &[u8]) -> Result<Self, PkcsError> {
        Ok(Self::new(decode_all(bytes)?))
    }

    pub fn encode(&self) -> Result<Vec<u8>, PkcsError> {
        Ok(self.request.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn certification_request(&self) -> &CertificationRequest {
        &self.request
    }

    pub fn subject(&self) -> &Name {
        self.request.certification_request_info().subject()
    }

    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        self.request.certification_request_info().subject_pk_info()
    }

    pub fn attributes(&self) -> &[Attribute] {
        self.request
            .certification_request_info()
            .attributes()
            .unwrap_or_default()
    }

    // The extensions of the extensionRequest attribute of PKCS#9, Bouncy Castle's
    // GetRequestedExtensions; None without one
    pub fn requested_extensions(&self) -> Result<Option<Extensions>, PkcsError> {
        let Some(attribute) = self
            .attributes()
            .iter()
            .find(|attribute| Pkcs9Attribute::EXTENSION_REQUEST == *attribute.attribute_type())
        else {
            return Ok(None);
        };
        let [AttributeValue::Other(value)] = attribute.values() else {
            return Err(PkcsError::InvalidRequest);
        };
        Ok(Some(decode_all(
            &value.encode_to_vec(&EncodingOptions::DER)?,
        )?))
    }

    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        self.request.signature_algorithm()
    }

    pub fn signature(&self) -> &[u8] {
        self.request.signature().as_bytes()
    }

    // The public key the request carries, Bouncy Castle's GetPublicKey
    pub fn public_key(&self, x509: &dyn X509Operator) -> Result<Box<dyn Params>, PkcsError> {
        Ok(x509.spki().decode(self.subject_public_key_info())?)
    }

    // Whether the signature verifies with the key the provider holds, as the DER of the
    // CertificationRequestInfo, which is what Bouncy Castle checks. For a request, that key is
    // its own: x509.verifier_factory_provider(public_key)
    pub fn is_signature_valid(
        &self,
        provider: &dyn VerifierFactoryProvider,
    ) -> Result<bool, PkcsError> {
        let info = self
            .request
            .certification_request_info()
            .encode_to_vec(&EncodingOptions::DER)?;
        let factory = provider.create_verifier_factory(self.signature_algorithm())?;
        let mut calculator = factory.create_calculator()?;
        calculator
            .write_all(&info)
            .map_err(tc_x509::X509Error::from)?;
        Ok(calculator.result().is_verified(self.signature())?)
    }

    // As is_signature_valid, with InvalidSignature for a signature that does not verify
    pub fn verify(&self, provider: &dyn VerifierFactoryProvider) -> Result<(), PkcsError> {
        if self.is_signature_valid(provider)? {
            Ok(())
        } else {
            Err(PkcsError::InvalidSignature)
        }
    }
}
