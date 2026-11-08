use std::any::Any;
use std::io::Write;
use std::sync::Arc;

use tc_algo_v2::generate::KeyPair;
use tc_algo_v2::{AlgoBuilder, DefaultAlgoBuilder, Params};
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509Operator, X509OperatorBuilder};

fn rsa_pair(oper: &dyn X509Operator) -> KeyPair {
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA").unwrap();
    // Small, since generating the primes is slow
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    key_gen.generate().unwrap()
}

// Checked with tc_algo_v2 directly, apart from the factory under test
fn verifies(public: &dyn Params, data: &[u8], signature: &[u8]) -> bool {
    let algo = DefaultAlgoBuilder::default().build();
    let mut verifier = algo.signer().get_by_name("SHA-256withRSA").unwrap();
    verifier.init(public).unwrap();
    verifier.update(data).unwrap();
    verifier.verify_signature(signature).unwrap()
}

#[test]
fn a_factory_signs_and_records_sha256_with_rsa_with_null_parameters() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (public, private) = rsa_pair(oper.as_ref()).into_parts();

    let factory = oper
        .signature_factory("SHA-256withRSA", private.into())
        .unwrap();
    assert_eq!(
        factory.algorithm().algorithm().to_string(),
        "1.2.840.113549.1.1.11"
    );
    assert!(factory.algorithm().parameters().is_some());

    let mut calculator = factory.create_calculator().unwrap();
    calculator.write_all(b"to be signed").unwrap();
    let signature = calculator.result().collect().unwrap();
    assert!(verifies(public.as_ref(), b"to be signed", &signature));
}

#[test]
fn an_alias_in_any_case_finds_the_row_and_one_key_serves_two_factories() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (_, private) = rsa_pair(oper.as_ref()).into_parts();
    let private: Arc<dyn Params> = private.into();

    let first = oper
        .signature_factory("sha256withrsa", private.clone())
        .unwrap();
    let second = oper
        .signature_factory("SHA-256withRSAEncryption", private)
        .unwrap();
    assert_eq!(first.algorithm(), second.algorithm());
}

#[test]
fn an_unknown_name_is_an_unknown_signer() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (_, private) = rsa_pair(oper.as_ref()).into_parts();

    let error = oper
        .signature_factory("NOPE", private.into())
        .err()
        .unwrap();
    assert!(matches!(error, X509Error::UnknownSigner));
}

struct OtherKey;

impl Params for OtherKey {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[test]
fn a_key_the_signer_refuses_is_reported_when_the_factory_is_made() {
    let oper = DefaultX509OperatorBuilder::default().build();

    let error = oper
        .signature_factory("SHA-256withRSA", Arc::new(OtherKey))
        .err()
        .unwrap();
    assert!(matches!(error, X509Error::Algo(_)));
}
