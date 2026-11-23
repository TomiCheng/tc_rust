use std::sync::Arc;

use tc_pkix::{
    PkixCertPath, PkixCertPathValidator, PkixError, PkixParameters, TrustAnchor, ValidatorReason,
};
use tc_x509::cert::X509Certificate;
use tc_x509::{DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder};

fn certificate(der: &[u8]) -> X509Certificate {
    X509Certificate::decode(der).unwrap()
}

fn x509() -> Arc<dyn X509Operator> {
    Arc::from(DefaultX509OperatorBuilder::default().build())
}

fn reason(result: Result<impl Sized, PkixError>) -> ValidatorReason {
    match result {
        Err(PkixError::Validator(error)) => error.reason(),
        Err(other) => panic!("not a validation failure: {other}"),
        Ok(_) => panic!("validated"),
    }
}

#[test]
fn a_leaf_issued_by_the_trusted_ca_validates() {
    let ca = certificate(include_bytes!("data/ca.der"));
    let leaf = certificate(include_bytes!("data/leaf.der"));
    let params = PkixParameters::new(vec![TrustAnchor::from_certificate(ca.clone())])
        .with_revocation_enabled(false);
    let result = PkixCertPathValidator::new(x509())
        .validate(&PkixCertPath::new(vec![leaf.clone()]), &params)
        .unwrap();
    assert_eq!(result.trust_anchor().trusted_certificate(), Some(&ca));
    assert_eq!(result.subject_public_key(), leaf.subject_public_key_info());
}

#[test]
fn a_leaf_without_its_ca_among_the_anchors_has_no_trust_anchor() {
    let leaf = certificate(include_bytes!("data/leaf.der"));
    let params = PkixParameters::new(vec![TrustAnchor::from_certificate(leaf.clone())])
        .with_revocation_enabled(false);
    let result =
        PkixCertPathValidator::new(x509()).validate(&PkixCertPath::new(vec![leaf]), &params);
    assert_eq!(reason(result), ValidatorReason::NoTrustAnchor);
}

#[test]
fn revocation_checking_that_cannot_be_done_does_not_pass() {
    let ca = certificate(include_bytes!("data/ca.der"));
    let leaf = certificate(include_bytes!("data/leaf.der"));
    let params = PkixParameters::new(vec![TrustAnchor::from_certificate(ca)]);
    let result =
        PkixCertPathValidator::new(x509()).validate(&PkixCertPath::new(vec![leaf]), &params);
    assert_eq!(
        reason(result),
        ValidatorReason::UndeterminedRevocationStatus
    );
}
