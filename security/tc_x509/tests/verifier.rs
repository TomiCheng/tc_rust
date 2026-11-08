use std::io::Write;
use std::sync::Arc;

use tc_algo_v2::Params;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::ext::BasicConstraints;
use tc_x509::cert::X509V3CertificateGenerator;
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::operator::signer::SignatureFactory;
use tc_x509::operator::verifier::VerifierFactory;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509Operator, X509OperatorBuilder};

const MESSAGE: &[u8] = b"to be signed";

fn keys(oper: &dyn X509Operator) -> (Arc<dyn Params>, Arc<dyn Params>) {
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA").unwrap();
    // Small, since generating the primes is slow
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let (public, private) = key_gen.generate().unwrap().into_parts();
    (public.into(), private.into())
}

fn sign(factory: &dyn SignatureFactory, data: &[u8]) -> Vec<u8> {
    let mut calculator = factory.create_calculator().unwrap();
    calculator.write_all(data).unwrap();
    calculator.result().collect().unwrap()
}

fn verify(factory: &dyn VerifierFactory, data: &[u8], signature: &[u8]) -> bool {
    let mut calculator = factory.create_calculator().unwrap();
    calculator.write_all(data).unwrap();
    calculator.result().is_verified(signature).unwrap()
}

#[test]
fn a_signature_verifies_and_a_changed_message_does_not() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (public, private) = keys(oper.as_ref());
    let signature = sign(
        oper.signature_factory("SHA-256withRSA", private)
            .unwrap()
            .as_ref(),
        MESSAGE,
    );

    let verifier = oper.verifier_factory("SHA-256withRSA", public).unwrap();
    assert!(verify(verifier.as_ref(), MESSAGE, &signature));
    assert!(!verify(verifier.as_ref(), b"to be signeD", &signature));
}

#[test]
fn the_provider_finds_the_row_by_the_algorithm_with_or_without_its_null() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (public, private) = keys(oper.as_ref());
    let signer = oper.signature_factory("SHA-256withRSA", private).unwrap();
    let signature = sign(signer.as_ref(), MESSAGE);
    let provider = oper.verifier_factory_provider(public);

    let with_null = provider
        .create_verifier_factory(signer.algorithm())
        .unwrap();
    assert!(verify(with_null.as_ref(), MESSAGE, &signature));

    let without = AlgorithmIdentifier::new(signer.algorithm().algorithm().clone());
    let without = provider.create_verifier_factory(&without).unwrap();
    assert!(verify(without.as_ref(), MESSAGE, &signature));
}

#[test]
fn an_algorithm_no_row_knows_is_an_unknown_signer() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (public, _) = keys(oper.as_ref());
    let provider = oper.verifier_factory_provider(public);

    let unknown = AlgorithmIdentifier::new("1.2.3".parse().unwrap());
    let error = provider.create_verifier_factory(&unknown).err().unwrap();
    assert!(matches!(error, X509Error::UnknownSigner));
}

#[test]
fn a_self_signed_certificate_verifies_with_the_key_it_holds() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (public, private) = keys(oper.as_ref());

    let mut generator = X509V3CertificateGenerator::new();
    generator.set_issuer_by_str("CN=Test CA").unwrap();
    generator.set_subject_by_str("CN=Test CA").unwrap();
    generator.set_validity_days(30).unwrap();
    generator.set_subject_public_key_info(oper.spki().encode(public.as_ref()).unwrap());
    generator
        .add_basic_constraints(BasicConstraints::ca(None))
        .unwrap();
    let signer = oper.signature_factory("SHA-256withRSA", private).unwrap();
    let certificate = generator.generate(signer.as_ref()).unwrap();

    // Everything from the certificate itself: its key, its algorithm, its signed part
    let key = oper
        .spki()
        .decode(certificate.subject_public_key_info())
        .unwrap();
    let provider = oper.verifier_factory_provider(key.into());
    let verifier = provider
        .create_verifier_factory(certificate.signature_algorithm())
        .unwrap();
    assert!(verify(
        verifier.as_ref(),
        certificate.tbs_certificate(),
        certificate.signature()
    ));
}
