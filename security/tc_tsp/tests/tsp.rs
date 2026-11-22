use std::sync::Arc;

use chrono::Utc;
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder, Params};
use tc_asn1::{Asn1Integer, Decode, DecodingOptions};
use tc_asn1_cmp::{PkiFailureInfo, PkiStatus};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_pkcs::{DefaultPkcsOperatorBuilder, PkcsOperatorBuilder};
use tc_tsp::{
    DefaultTspOperatorBuilder, TimeStampRequest, TimeStampRequestGenerator, TimeStampResponse,
    TimeStampResponseGenerator, TimeStampTokenGenerator, TspError, TspOperatorBuilder,
};
use tc_x509::cert::X509Certificate;

const CONTENT: &[u8] = include_bytes!("data/tsp_content.txt");
const SHA1: &str = "1.3.14.3.2.26";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";

fn tsa() -> X509Certificate {
    X509Certificate::decode(include_bytes!("data/tsp_tsa.der")).unwrap()
}

fn ca() -> X509Certificate {
    X509Certificate::decode(include_bytes!("data/tsp_ca.der")).unwrap()
}

fn tsa_key() -> Arc<dyn Params> {
    let der = include_bytes!("data/tsp_tsa_key.der");
    let info = PrivateKeyInfo::decode(der, &DecodingOptions::default())
        .unwrap()
        .1;
    let pkcs = DefaultPkcsOperatorBuilder::default().build();
    Arc::from(pkcs.private_key_info().decode(&info).unwrap())
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let algo = DefaultAlgoBuilder::default().build();
    algo.digest().calculate_by_name("SHA-256", data).unwrap()
}

fn generator(ess_digest: &str, issuer_serial: bool) -> TimeStampTokenGenerator {
    TimeStampTokenGenerator::new(
        tsa_key(),
        "SHA-256withRSA",
        tsa(),
        Some("1.2.3.4.1".parse().unwrap()),
    )
    .unwrap()
    .with_ess_digest(ess_digest.parse().unwrap())
    .with_issuer_serial(issuer_serial)
}

#[test]
fn what_openssl_answered_validates_against_its_request_and_the_tsa_certificate() {
    let oper = DefaultTspOperatorBuilder::default().build();
    let request = TimeStampRequest::decode(include_bytes!("data/tsp_request.tsq")).unwrap();
    assert!(request.cert_req());
    assert_eq!(request.message_imprint_digest(), sha256(CONTENT).as_slice());

    let response = TimeStampResponse::decode(include_bytes!("data/tsp_response.tsr")).unwrap();
    assert_eq!(response.status(), PkiStatus::Granted);
    response.validate(&request).unwrap();
    let token = response.time_stamp_token().unwrap();
    assert_eq!(token.tst_info().policy().to_string(), "1.2.3.4.1");
    assert_eq!(token.certificates().len(), 2);
    oper.validate_token(token, &tsa()).unwrap();

    // the CA did not sign the token
    let error = oper.validate_token(token, &ca()).unwrap_err();
    assert!(matches!(error, TspError::Validation(_)));
}

#[test]
fn a_response_made_here_validates_with_each_signing_certificate_form() {
    let oper = DefaultTspOperatorBuilder::default().build();
    let mut request_generator = TimeStampRequestGenerator::new();
    request_generator.set_cert_req(true);
    let request = request_generator
        .generate(
            SHA256.parse().unwrap(),
            &sha256(CONTENT),
            Some(Asn1Integer::from(42)),
        )
        .unwrap();
    let request = TimeStampRequest::decode(&request.encode().unwrap()).unwrap();

    for (ess, issuer_serial) in [(SHA1, false), (SHA256, true)] {
        let responder = TimeStampResponseGenerator::new(
            generator(ess, issuer_serial),
            vec![SHA256.parse().unwrap()],
        );
        let response = oper
            .generate_response(&responder, &request, Asn1Integer::from(7), Utc::now())
            .unwrap();
        let response = TimeStampResponse::decode(&response.encode().unwrap()).unwrap();
        assert_eq!(response.status(), PkiStatus::Granted);
        response.validate(&request).unwrap();
        let token = response.time_stamp_token().unwrap();
        assert_eq!(token.tst_info().nonce(), Some(&Asn1Integer::from(42)));
        assert_eq!(token.certificates(), [tsa()]);
        oper.validate_token(token, &tsa()).unwrap();
    }
}

#[test]
fn the_openssl_request_is_answered_here() {
    let oper = DefaultTspOperatorBuilder::default().build();
    let request = TimeStampRequest::decode(include_bytes!("data/tsp_request.tsq")).unwrap();
    let responder =
        TimeStampResponseGenerator::new(generator(SHA256, false), vec![SHA256.parse().unwrap()]);
    let response = oper
        .generate_response(&responder, &request, Asn1Integer::from(8), Utc::now())
        .unwrap();
    response.validate(&request).unwrap();
    oper.validate_token(response.time_stamp_token().unwrap(), &tsa())
        .unwrap();
}

#[test]
fn a_request_the_tsa_does_not_accept_is_answered_with_a_rejection() {
    let oper = DefaultTspOperatorBuilder::default().build();
    let mut request_generator = TimeStampRequestGenerator::new();
    let responder =
        TimeStampResponseGenerator::new(generator(SHA1, false), vec![SHA256.parse().unwrap()])
            .with_accepted_policies(vec!["1.2.3.4.1".parse().unwrap()]);

    let sha1 = request_generator
        .generate(SHA1.parse().unwrap(), &[0; 20], None)
        .unwrap();
    let short = request_generator
        .generate(SHA256.parse().unwrap(), &[0; 20], None)
        .unwrap();
    request_generator.set_req_policy("1.2.3.4.9".parse().unwrap());
    let policy = request_generator
        .generate(SHA256.parse().unwrap(), &[0; 32], None)
        .unwrap();
    for (request, expected) in [
        (sha1, PkiFailureInfo::BAD_ALG),
        (short, PkiFailureInfo::BAD_DATA_FORMAT),
        (policy, PkiFailureInfo::UNACCEPTED_POLICY),
    ] {
        let response = oper
            .generate_response(&responder, &request, Asn1Integer::from(1), Utc::now())
            .unwrap();
        let response = TimeStampResponse::decode(&response.encode().unwrap()).unwrap();
        assert_eq!(response.status(), PkiStatus::Rejection);
        assert_eq!(response.fail_info(), Some(&expected));
        assert!(response.time_stamp_token().is_none());
        response.validate(&request).unwrap();
    }
}

#[test]
fn a_certificate_not_solely_for_time_stamping_cannot_sign_tokens() {
    let result = TimeStampTokenGenerator::new(tsa_key(), "SHA-256withRSA", ca(), None);
    assert!(matches!(result, Err(TspError::Validation(_))));
}
