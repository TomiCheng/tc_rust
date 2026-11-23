use tc_algo::digest::DigestProvider;
use tc_asn1::{Asn1OctetString, Asn1Oid, Encode, EncodingOptions};
use tc_asn1_ocsp::{CertId, OcspId, OcspRequest, Request, Signature, TbsRequest};
use tc_asn1_x509::{
    alg::AlgorithmIdentifier,
    cert::Certificate,
    ext::{Extension, Extensions},
};
use tc_x509::{
    cert::X509Certificate,
    operator::{signer::SignatureFactory, verifier::VerifierFactoryProvider},
};

use crate::{OcspError, der, sign, verify};

/// Builds a CertID from the certificate's issuer name and the issuer's public key.
pub fn certificate_id(
    certificate: &X509Certificate,
    issuer: &X509Certificate,
    digest: &Asn1Oid,
    digests: &dyn DigestProvider,
) -> Result<CertId, OcspError> {
    if !certificate.issuer().equivalent(issuer.subject()) {
        return Err(OcspError::CertificateMismatch);
    }
    let name = certificate.issuer().encode_to_vec(&EncodingOptions::DER)?;
    let key = issuer.subject_public_key_info().subject_public_key();
    Ok(CertId::new(
        AlgorithmIdentifier::new(digest.clone()),
        Asn1OctetString::new(&digests.calculate_by_oid(digest, &name)?),
        Asn1OctetString::new(&digests.calculate_by_oid(digest, key.as_bytes())?),
        certificate.serial_number().clone(),
    ))
}

/// Builds an unsigned, single-certificate request with an optional nonce.
pub fn request_for(cert_id: CertId, nonce: Option<&[u8]>) -> Result<OcspRequest, OcspError> {
    let mut request = TbsRequest::new(vec![Request::new(cert_id)]);
    if let Some(nonce) = nonce {
        if nonce.len() < 32 {
            return Err(OcspError::Malformed(
                "request nonce must contain at least 32 bytes",
            ));
        }
        request = request.with_request_extensions(Extensions::new(vec![nonce_extension(nonce)?])?);
    }
    Ok(OcspRequest::new(request))
}

/// Encodes a caller-generated nonce as a noncritical extension.
pub fn nonce_extension(nonce: &[u8]) -> Result<Extension, OcspError> {
    if !(1..=128).contains(&nonce.len()) {
        return Err(OcspError::Malformed("nonce must contain 1 to 128 bytes"));
    }
    let encoded = Asn1OctetString::new(nonce).encode_to_vec(&EncodingOptions::DER)?;
    Ok(Extension::new(OcspId::NONCE.oid(), false, &encoded))
}

pub fn decode_request(bytes: &[u8]) -> Result<OcspRequest, OcspError> {
    der(bytes)
}

/// Signs an OCSP request with the factory's key and algorithm.
pub fn sign_request(
    request: TbsRequest,
    factory: &dyn SignatureFactory,
    certs: Vec<Certificate>,
) -> Result<OcspRequest, OcspError> {
    if request.requestor_name().is_none() || request.request_list().is_empty() {
        return Err(OcspError::Malformed(
            "signed request needs a requestor name and certificates to query",
        ));
    }
    let mut signature = Signature::new(factory.algorithm().clone(), sign(&request, factory)?);
    if !certs.is_empty() {
        signature = signature.with_certs(certs);
    }
    Ok(OcspRequest::new(request).with_optional_signature(signature))
}

/// Verifies the signature using the provider's key. The caller checks request syntax and authenticates the requestor.
pub fn verify_request_signature(
    request: &OcspRequest,
    provider: &dyn VerifierFactoryProvider,
) -> Result<(), OcspError> {
    let signature = request
        .optional_signature()
        .ok_or(OcspError::InvalidSignature)?;
    verify(
        request.tbs_request(),
        signature.signature_algorithm(),
        signature.signature(),
        provider,
    )
}
