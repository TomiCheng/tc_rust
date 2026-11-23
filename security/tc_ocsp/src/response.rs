use chrono::{DateTime, TimeDelta, Utc};
use tc_algo::{ErrorKind, digest::DigestProvider};
use tc_asn1::{
    Asn1Object, Asn1OctetString, DecodingContext, DecodingOptions, Encode, EncodingOptions,
};
use tc_asn1_ocsp::{
    BasicOcspResponse, OcspId, OcspResponse, OcspResponseStatus, ResponderId, ResponseBytes,
    ResponseData, SingleResponse,
};
use tc_asn1_x509::{
    cert::{Certificate, Time},
    ext::{Extensions, KeyPurposeId, KeyUsage},
};
use tc_x509::{
    X509Operator,
    cert::X509Certificate,
    extension::key_identifier_of,
    operator::{signer::SignatureFactory, verifier::VerifierFactoryProvider},
};

use crate::{OcspError, certificate_id, der, sign, verifier, verify};

pub fn decode_response(bytes: &[u8]) -> Result<OcspResponse, OcspError> {
    der(bytes)
}

/// Extracts the BasicOCSPResponse from a successful OCSP response.
pub fn basic_response(response: &OcspResponse) -> Result<BasicOcspResponse, OcspError> {
    let status = *response.response_status();
    if status != OcspResponseStatus::Successful {
        return Err(OcspError::ResponseStatus(status));
    }
    let bytes = response
        .response_bytes()
        .ok_or(OcspError::Malformed("missing response bytes"))?;
    if *bytes.response_type() != OcspId::BASIC.oid() {
        return Err(OcspError::UnsupportedResponseType);
    }
    der(bytes.response().as_bytes())
}

/// Signs response data and wraps it in a successful OCSPResponse.
pub fn sign_response(
    data: ResponseData,
    factory: &dyn SignatureFactory,
    certs: Vec<Certificate>,
) -> Result<OcspResponse, OcspError> {
    if data.responses().is_empty() {
        return Err(OcspError::Malformed("empty response list"));
    }
    let signature = sign(&data, factory)?;
    let mut basic = BasicOcspResponse::new(data, factory.algorithm().clone(), signature);
    if !certs.is_empty() {
        basic = basic.with_certs(certs);
    }
    let encoded = basic.encode_to_vec(&EncodingOptions::DER)?;
    Ok(
        OcspResponse::new(OcspResponseStatus::Successful).with_response_bytes(ResponseBytes::new(
            OcspId::BASIC.oid(),
            Asn1OctetString::new(&encoded),
        )),
    )
}

/// Checks the cryptographic signature with a caller-supplied key.
pub fn verify_response_signature(
    response: &BasicOcspResponse,
    provider: &dyn VerifierFactoryProvider,
) -> Result<(), OcspError> {
    verify(
        response.tbs_response_data(),
        response.signature_algorithm(),
        response.signature(),
        provider,
    )
}

/// Policy for accepting status for a certificate at a given time.
#[derive(Clone, Copy, Debug)]
pub struct ResponseValidation<'a> {
    at: DateTime<Utc>,
    max_age: TimeDelta,
    expected_nonce: Option<&'a [u8]>,
}

impl<'a> ResponseValidation<'a> {
    /// Creates a validation policy with a maximum age for thisUpdate.
    pub fn new(at: DateTime<Utc>, max_age: TimeDelta) -> Self {
        Self {
            at,
            max_age,
            expected_nonce: None,
        }
    }

    pub fn with_expected_nonce(mut self, nonce: &'a [u8]) -> Self {
        self.expected_nonce = Some(nonce);
        self
    }

    pub fn at(&self) -> DateTime<Utc> {
        self.at
    }

    pub fn max_age(&self) -> TimeDelta {
        self.max_age
    }

    pub fn expected_nonce(&self) -> Option<&'a [u8]> {
        self.expected_nonce
    }
}

impl ResponseValidation<'_> {
    /// Validates one certificate's status against a previously trusted issuer.
    ///
    /// Supply the issuer as responder for a CA-signed response. A delegated
    /// responder must chain directly to the issuer and have the OCSP signing EKU.
    /// The caller applies its certificate path and delegated responder revocation policies.
    pub fn validate<'a>(
        &self,
        response: &'a BasicOcspResponse,
        certificate: &X509Certificate,
        issuer: &X509Certificate,
        responder: &X509Certificate,
        digests: &dyn DigestProvider,
        x509: &dyn X509Operator,
    ) -> Result<&'a SingleResponse, OcspError> {
        let data = response.tbs_response_data();
        if data.version() != 0.into() {
            return Err(OcspError::Malformed("unsupported response version"));
        }
        if !certificate.issuer().equivalent(issuer.subject()) {
            return Err(OcspError::CertificateMismatch);
        }
        let issuer_verifier = verifier(x509, issuer)?;
        certificate.verify(&*issuer_verifier)?;
        let produced_at: DateTime<Utc> = (*data.produced_at()).into();
        let responder_id_matches = match data.responder_id() {
            ResponderId::ByName(name) => name.equivalent(responder.subject()),
            ResponderId::ByKey(hash) => {
                hash.as_bytes() == key_identifier_of(responder.subject_public_key_info())
            }
        };
        if !responder_id_matches {
            return Err(OcspError::UnauthorizedResponder);
        }
        if responder.certificate() != issuer.certificate() {
            let time = Time::try_from(produced_at)?;
            if !responder.issuer().equivalent(issuer.subject()) || !responder.is_valid_at(&time) {
                return Err(OcspError::UnauthorizedResponder);
            }
            let extensions = responder
                .extensions()
                .ok_or(OcspError::UnauthorizedResponder)?;
            let mut ctx = DecodingContext::new(DecodingOptions::default());
            let eku = extensions.get_extended_key_usage(&mut ctx)?;
            let usage = extensions.get_key_usage(&mut ctx)?;
            if !eku.is_some_and(|eku| eku.contains(KeyPurposeId::OCSP_SIGNING.oid()))
                || usage.is_some_and(|usage| !usage.contains(KeyUsage::DIGITAL_SIGNATURE))
            {
                return Err(OcspError::UnauthorizedResponder);
            }
            responder.verify(&*issuer_verifier)?;
        }
        verify_response_signature(response, &*verifier(x509, responder)?)?;
        check_extensions(data.response_extensions(), true)?;
        let nonce = data
            .response_extensions()
            .and_then(|extensions| extensions.get(OcspId::NONCE.oid()))
            .map(|extension| der::<Asn1OctetString>(extension.extn_value()))
            .transpose()?;
        if nonce
            .as_ref()
            .is_some_and(|nonce| !(1..=128).contains(&nonce.as_bytes().len()))
        {
            return Err(OcspError::Malformed("invalid response nonce length"));
        }
        if let Some(expected) = self.expected_nonce {
            if nonce.as_ref().map(Asn1OctetString::as_bytes) != Some(expected) {
                return Err(OcspError::NonceMismatch);
            }
        }

        let mut matching = None;
        for entry in data.responses() {
            let id = entry.cert_id();
            if id.serial_number() != certificate.serial_number() {
                continue;
            }
            let algorithm = id.hash_algorithm();
            if !matches!(algorithm.parameters(), None | Some(Asn1Object::Null(_))) {
                continue;
            }
            let expected = match certificate_id(certificate, issuer, algorithm.algorithm(), digests)
            {
                Ok(id) => id,
                Err(OcspError::Crypto(error)) if error.kind() == ErrorKind::UnknownDigest => {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if id.issuer_name_hash() == expected.issuer_name_hash()
                && id.issuer_key_hash() == expected.issuer_key_hash()
                && matching.replace(entry).is_some()
            {
                return Err(OcspError::Malformed("duplicate status for certificate"));
            }
        }
        let entry = matching.ok_or(OcspError::CertificateMismatch)?;
        check_extensions(entry.single_extensions(), false)?;
        let this_update: DateTime<Utc> = (*entry.this_update()).into();
        let next_update: Option<DateTime<Utc>> = entry.next_update().copied().map(Into::into);
        if produced_at > self.at
            || this_update > produced_at
            || self.at.signed_duration_since(this_update) > self.max_age
            || next_update.is_some_and(|next| next < self.at)
        {
            return Err(OcspError::InvalidTime);
        }
        Ok(entry)
    }
}

fn check_extensions(extensions: Option<&Extensions>, allow_nonce: bool) -> Result<(), OcspError> {
    if extensions.is_some_and(|extensions| {
        extensions.extensions().iter().any(|extension| {
            extension.critical() && !(allow_nonce && *extension.extn_id() == OcspId::NONCE.oid())
        })
    }) {
        return Err(OcspError::UnsupportedCriticalExtension);
    }
    Ok(())
}
