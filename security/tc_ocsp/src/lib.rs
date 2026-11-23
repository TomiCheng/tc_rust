//! OCSP request and response operations for RFC 6960.
//!
//! Callers supply DER messages and cryptographic factories. Certificate path
//! validation and network transport are handled by the application.

mod error;
mod request;
mod response;

pub use error::OcspError;
pub use request::{
    certificate_id, decode_request, nonce_extension, request_for, sign_request,
    verify_request_signature,
};
pub use response::{
    ResponseValidation, basic_response, decode_response, sign_response, verify_response_signature,
};

use std::sync::Arc;

use tc_asn1::{Asn1BitString, Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_x509::operator::{signer::SignatureFactory, verifier::VerifierFactoryProvider};
use tc_x509::{X509Operator, cert::X509Certificate};

fn der<T: Decode + Encode>(bytes: &[u8]) -> Result<T, OcspError> {
    let (used, value) = T::decode_der(bytes, &DecodingOptions::default())?;
    if used != bytes.len() {
        return Err(Asn1Error::TrailingData.into());
    }
    if value.encode_to_vec(&EncodingOptions::DER)? != bytes {
        return Err(OcspError::Malformed("noncanonical DER"));
    }
    Ok(value)
}

fn sign(value: &impl Encode, factory: &dyn SignatureFactory) -> Result<Asn1BitString, OcspError> {
    let mut calculator = factory.create_calculator()?;
    calculator.write_all(&value.encode_to_vec(&EncodingOptions::DER)?)?;
    Ok(Asn1BitString::from_bytes(&calculator.result().collect()?))
}

fn verify(
    value: &impl Encode,
    algorithm: &AlgorithmIdentifier,
    signature: &Asn1BitString,
    provider: &dyn VerifierFactoryProvider,
) -> Result<(), OcspError> {
    if signature.unused_bits() != 0 {
        return Err(OcspError::Malformed("signature must be octet aligned"));
    }
    let factory = provider.create_verifier_factory(algorithm)?;
    let mut calculator = factory.create_calculator()?;
    calculator.write_all(&value.encode_to_vec(&EncodingOptions::DER)?)?;
    if !calculator.result().is_verified(signature.as_bytes())? {
        return Err(OcspError::InvalidSignature);
    }
    Ok(())
}

fn verifier(
    x509: &dyn X509Operator,
    cert: &X509Certificate,
) -> Result<Box<dyn VerifierFactoryProvider>, OcspError> {
    let key = x509.spki().decode(cert.subject_public_key_info())?;
    Ok(x509.verifier_factory_provider(Arc::from(key)))
}
