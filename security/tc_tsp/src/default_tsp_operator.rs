use std::sync::Arc;

use chrono::{DateTime, Utc};
use tc_algo::Algo;
use tc_asn1::{
    Asn1GeneralizedTime, Asn1Integer, Asn1OctetString, Asn1Oid, Encode, EncodingOptions,
};
use tc_asn1_cmp::PkiFailureInfo;
use tc_asn1_ess::{EssAttribute, EssCertId, EssCertIdV2, SigningCertificate, SigningCertificateV2};
use tc_asn1_tsp::TstInfo;
use tc_asn1_x500::{Attribute, AttributeValue};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::attr::IssuerSerial;
use tc_asn1_x509::cert::Time;
use tc_asn1_x509::name::{GeneralName, GeneralNames};
use tc_cms::CmsOperator;
use tc_cms::signed::{CmsSignedDataGenerator, SignerInfoGenerator};
use tc_x509::X509Operator;
use tc_x509::cert::X509Certificate;

use crate::der::convert;
use crate::token::{CertId, ID_CT_TST_INFO, SHA1};
use crate::{
    TimeStampRequest, TimeStampResponse, TimeStampResponseGenerator, TimeStampToken,
    TimeStampTokenGenerator, TspError, TspOperator, validate_certificate,
};

pub(crate) struct DefaultTspOperator {
    algo: Arc<dyn Algo>,
    x509: Arc<dyn X509Operator>,
    cms: Arc<dyn CmsOperator>,
}

impl DefaultTspOperator {
    pub(crate) fn new(
        algo: Arc<dyn Algo>,
        x509: Arc<dyn X509Operator>,
        cms: Arc<dyn CmsOperator>,
    ) -> Self {
        Self { algo, x509, cms }
    }

    // ESS 的 signingCertificate：SHA-1 時是 v1，其他摘要是 v2，同 BC 的 TableGen 與 TableGen2
    fn signing_certificate(
        &self,
        generator: &TimeStampTokenGenerator,
    ) -> Result<Attribute, TspError> {
        let certificate = &generator.certificate;
        let hash = self
            .algo
            .digest()
            .calculate_by_oid(&generator.ess_digest, &certificate.encode()?)?;
        let issuer_serial = generator
            .issuer_serial
            .then(|| -> Result<IssuerSerial, TspError> {
                Ok(IssuerSerial::new(
                    GeneralNames::new(vec![GeneralName::DirectoryName(
                        certificate.issuer().clone(),
                    )])?,
                    certificate.serial_number().clone(),
                ))
            })
            .transpose()?;
        let (oid, value) = if SHA1 == generator.ess_digest {
            let mut id = EssCertId::new(Asn1OctetString::new(&hash));
            if let Some(issuer_serial) = issuer_serial {
                id = id.with_issuer_serial(issuer_serial);
            }
            (
                EssAttribute::SIGNING_CERTIFICATE.oid(),
                convert(&SigningCertificate::new(vec![id]))?,
            )
        } else {
            let mut id = EssCertIdV2::new(Asn1OctetString::new(&hash))
                .with_hash_algorithm(AlgorithmIdentifier::new(generator.ess_digest.clone()));
            if let Some(issuer_serial) = issuer_serial {
                id = id.with_issuer_serial(issuer_serial);
            }
            (
                EssAttribute::SIGNING_CERTIFICATE_V2.oid(),
                convert(&SigningCertificateV2::new(vec![id]))?,
            )
        };
        Ok(Attribute::new(oid, vec![AttributeValue::Other(value)])?)
    }
}

impl TspOperator for DefaultTspOperator {
    fn validate_request(
        &self,
        request: &TimeStampRequest,
        algorithms: &[Asn1Oid],
        policies: &[Asn1Oid],
        extensions: &[Asn1Oid],
    ) -> Result<(), TspError> {
        let algorithm = request.message_imprint_algorithm().algorithm();
        if !algorithms.contains(algorithm) {
            return Err(TspError::Rejected(PkiFailureInfo::BAD_ALG));
        }
        if !policies.is_empty() {
            if let Some(policy) = request.req_policy() {
                if !policies.contains(policy) {
                    return Err(TspError::Rejected(PkiFailureInfo::UNACCEPTED_POLICY));
                }
            }
        }
        if let Some(requested) = request.extensions() {
            if !extensions.is_empty()
                && requested
                    .extensions()
                    .iter()
                    .any(|extension| !extensions.contains(extension.extn_id()))
            {
                return Err(TspError::Rejected(PkiFailureInfo::UNACCEPTED_EXTENSION));
            }
        }
        let length = self
            .algo
            .digest()
            .get_by_oid(algorithm)
            .map_err(|_| TspError::Rejected(PkiFailureInfo::BAD_ALG))?
            .digest_size();
        if length != request.message_imprint_digest().len() {
            return Err(TspError::Rejected(PkiFailureInfo::BAD_DATA_FORMAT));
        }
        Ok(())
    }

    fn generate_token(
        &self,
        generator: &TimeStampTokenGenerator,
        request: &TimeStampRequest,
        serial_number: Asn1Integer,
        gen_time: DateTime<Utc>,
    ) -> Result<TimeStampToken, TspError> {
        let request_info = request.time_stamp_req();
        let policy = request
            .req_policy()
            .or(generator.policy.as_ref())
            .ok_or(TspError::Rejected(PkiFailureInfo::UNACCEPTED_POLICY))?
            .clone();
        let mut info = TstInfo::new(
            policy,
            request_info.message_imprint().clone(),
            serial_number,
            Asn1GeneralizedTime::try_from(gen_time)?,
        )
        .with_ordering(generator.ordering);
        if let Some(accuracy) = &generator.accuracy {
            info = info.with_accuracy(accuracy.clone());
        }
        if let Some(nonce) = request.nonce() {
            info = info.with_nonce(nonce.clone());
        }
        if let Some(tsa) = &generator.tsa {
            info = info.with_tsa(tsa.clone());
        }
        if let Some(extensions) = request.extensions() {
            info = info.with_extensions(extensions.clone());
        }
        let content = info.encode_to_vec(&EncodingOptions::DER)?;

        let factory = self
            .x509
            .signature_factory(&generator.signature, generator.private_key.clone())?;
        let signer = SignerInfoGenerator::new(factory, &generator.certificate)?
            .with_signed_attribute(self.signing_certificate(generator)?);
        let mut signed = CmsSignedDataGenerator::new();
        signed.set_content_type(ID_CT_TST_INFO.oid());
        signed.add_signer(signer);
        if request.cert_req() {
            signed.add_certificate(generator.certificate.clone());
            signed.add_certificates(generator.certificates.iter().cloned());
        }
        let signed = self.cms.signed_data().generate(&signed, &content, true)?;
        TimeStampToken::new(signed)
    }

    fn generate_response(
        &self,
        generator: &TimeStampResponseGenerator,
        request: &TimeStampRequest,
        serial_number: Asn1Integer,
        gen_time: DateTime<Utc>,
    ) -> Result<TimeStampResponse, TspError> {
        let checked = self
            .validate_request(
                request,
                &generator.accepted_algorithms,
                &generator.accepted_policies,
                &generator.accepted_extensions,
            )
            .and_then(|()| {
                self.generate_token(&generator.token_generator, request, serial_number, gen_time)
            });
        match checked {
            Ok(token) => TimeStampResponse::granted(token),
            Err(TspError::Rejected(fail_info)) => Ok(TimeStampResponse::rejected(fail_info)),
            Err(error) => Err(error),
        }
    }

    fn validate_token(
        &self,
        token: &TimeStampToken,
        certificate: &X509Certificate,
    ) -> Result<(), TspError> {
        let encoded = certificate.encode()?;
        let (digest, expected, issuer_serial) = match token.cert_id() {
            CertId::V1(id) => (SHA1.oid(), id.cert_hash(), id.issuer_serial()),
            CertId::V2(id) => (
                id.hash_algorithm().algorithm().clone(),
                id.cert_hash(),
                id.issuer_serial(),
            ),
        };
        let hash = self.algo.digest().calculate_by_oid(&digest, &encoded)?;
        if !fixed_time_eq(&hash, expected.as_bytes()) {
            return Err(TspError::Validation(
                "certificate hash does not match certID hash",
            ));
        }
        if let Some(issuer_serial) = issuer_serial {
            if issuer_serial.serial() != certificate.serial_number() {
                return Err(TspError::Validation(
                    "certificate serial number does not match certID for signature",
                ));
            }
            let named = issuer_serial.issuer().names().iter().any(|name| {
                matches!(name, GeneralName::DirectoryName(issuer) if issuer.equivalent(certificate.issuer()))
            });
            if !named {
                return Err(TspError::Validation(
                    "certificate name does not match certID for signature",
                ));
            }
        }
        validate_certificate(certificate)?;
        let gen_time = Time::try_from(DateTime::<Utc>::from(*token.tst_info().gen_time()))?;
        if !certificate.is_valid_at(&gen_time) {
            return Err(TspError::Validation(
                "certificate not valid when time stamp created",
            ));
        }
        self.cms
            .signed_data()
            .verify(token.signed_data(), token.signer(), certificate)
            .map_err(|error| match error {
                tc_cms::CmsError::InvalidSignature => {
                    TspError::Validation("signature not created by certificate")
                }
                other => TspError::Cms(other),
            })
    }
}

fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}
