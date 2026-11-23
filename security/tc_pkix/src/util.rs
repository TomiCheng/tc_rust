use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::Utc;
use tc_asn1::{Asn1Error, Asn1Oid, DecodeInner, DecodingContext, DecodingOptions};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::{SubjectPublicKeyInfo, Time};
use tc_asn1_x509::ext::Extensions;
use tc_x509::X509Operator;
use tc_x509::cert::X509Certificate;
use tc_x509::crl::X509Crl;

use crate::{CertPathValidatorError, TrustAnchor, ValidatorReason};

pub(crate) const ANY_POLICY: &str = "2.5.29.32.0";
const ID_DSA: &str = "1.2.840.10040.4.1";

pub(crate) fn oid(text: &str) -> Asn1Oid {
    text.parse().expect("a constant OID")
}

pub(crate) fn any_policy() -> Asn1Oid {
    oid(ANY_POLICY)
}

pub(crate) fn now() -> Time {
    Time::try_from(Utc::now()).expect("the current time fits a certificate time")
}

pub(crate) fn error(
    message: impl Into<String>,
    index: Option<usize>,
    reason: ValidatorReason,
) -> CertPathValidatorError {
    CertPathValidatorError::new(message, index, reason)
}

// 擴充解不開時的錯誤，BC 以 Unspecified 包住解碼例外
pub(crate) fn decode_error(
    message: &str,
    index: Option<usize>,
    source: Asn1Error,
) -> CertPathValidatorError {
    error(message, index, ValidatorReason::Unspecified).with_source(source)
}

pub(crate) fn extension<T: DecodeInner>(
    extensions: Option<&Extensions>,
    id: &Asn1Oid,
) -> Result<Option<T>, Asn1Error> {
    let Some(extensions) = extensions else {
        return Ok(None);
    };
    let mut context = DecodingContext::new(DecodingOptions::default());
    extensions.get_as(id.clone(), &mut context)
}

pub(crate) fn certificate_extension<T: DecodeInner>(
    certificate: &X509Certificate,
    id: &Asn1Oid,
) -> Result<Option<T>, Asn1Error> {
    extension(certificate.extensions(), id)
}

pub(crate) fn crl_extension<T: DecodeInner>(
    crl: &X509Crl,
    id: &Asn1Oid,
) -> Result<Option<T>, Asn1Error> {
    extension(crl.extensions(), id)
}

// BC 的 HasCriticalExtension；v3 以前的憑證沒有擴充
pub(crate) fn has_critical_extension(certificate: &X509Certificate, id: &Asn1Oid) -> bool {
    critical(certificate.extensions(), id)
}

pub(crate) fn crl_has_critical_extension(crl: &X509Crl, id: &Asn1Oid) -> bool {
    critical(crl.extensions(), id)
}

fn critical(extensions: Option<&Extensions>, id: &Asn1Oid) -> bool {
    extensions
        .and_then(|extensions| extensions.get(id.clone()))
        .is_some_and(|extension| extension.critical())
}

pub(crate) fn critical_extension_oids(extensions: Option<&Extensions>) -> BTreeSet<Asn1Oid> {
    extensions
        .map(|extensions| {
            extensions
                .extensions()
                .iter()
                .filter(|extension| extension.critical())
                .map(|extension| extension.extn_id().clone())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn is_self_issued(certificate: &X509Certificate) -> bool {
    certificate.subject().equivalent(certificate.issuer())
}

// 用 SPKI 的公鑰驗憑證的簽章
pub(crate) fn verify_certificate(
    x509: &dyn X509Operator,
    certificate: &X509Certificate,
    public_key: &SubjectPublicKeyInfo,
) -> Result<(), tc_x509::X509Error> {
    let key = x509.spki().decode(public_key)?;
    let provider = x509.verifier_factory_provider(Arc::from(key));
    certificate.verify(&*provider)
}

pub(crate) fn verify_crl(
    x509: &dyn X509Operator,
    crl: &X509Crl,
    public_key: &SubjectPublicKeyInfo,
) -> Result<(), tc_x509::X509Error> {
    let key = x509.spki().decode(public_key)?;
    let provider = x509.verifier_factory_provider(Arc::from(key));
    crl.verify(&*provider)
}

// BC 的 FindTrustAnchor：簽發者名稱相符、而且公鑰驗得過簽章的信任錨；都驗不過時回傳第一個失敗
pub(crate) fn find_trust_anchor<'a>(
    x509: &dyn X509Operator,
    certificate: &X509Certificate,
    anchors: &'a [TrustAnchor],
) -> Result<Option<&'a TrustAnchor>, tc_x509::X509Error> {
    let mut first_failure = None;
    for anchor in anchors {
        if !certificate.issuer().equivalent(anchor.subject()) {
            continue;
        }
        match verify_certificate(x509, certificate, anchor.subject_public_key_info()) {
            Ok(()) => return Ok(Some(anchor)),
            Err(failure) => {
                first_failure.get_or_insert(failure);
            }
        }
    }
    match first_failure {
        Some(failure) => Err(failure),
        None => Ok(None),
    }
}

// BC 的 GetNextWorkingKey：DSA 公鑰沒帶參數時，從往上的憑證繼承；以 SPKI 補上參數表示
pub(crate) fn next_working_key(
    certificates: &[X509Certificate],
    index: usize,
) -> Result<SubjectPublicKeyInfo, CertPathValidatorError> {
    let spki = certificates[index].subject_public_key_info();
    let dsa = oid(ID_DSA);
    if *spki.algorithm().algorithm() != dsa || spki.algorithm().parameters().is_some() {
        return Ok(spki.clone());
    }
    for parent in &certificates[index + 1..] {
        let parent = parent.subject_public_key_info();
        if *parent.algorithm().algorithm() != dsa {
            break;
        }
        if let Some(parameters) = parent.algorithm().parameters() {
            let algorithm = AlgorithmIdentifier::with_parameters(dsa, parameters.clone());
            return Ok(SubjectPublicKeyInfo::new(
                algorithm,
                spki.subject_public_key().clone(),
            ));
        }
    }
    Err(error(
        "DSA parameters cannot be inherited from previous certificate.",
        None,
        ValidatorReason::Unspecified,
    ))
}
