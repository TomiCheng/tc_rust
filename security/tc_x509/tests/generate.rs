use std::sync::Arc;

use tc_algo_v2::{AlgoBuilder, DefaultAlgoBuilder, Params};
use tc_asn1::{Asn1Integer, Encode, EncodingOptions};
use tc_asn1_x509::cert::Version;
use tc_asn1_x509::ext::BasicConstraints;
use tc_x509::cert::{X509Certificate, X509V3CertificateGenerator};
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509Operator, X509OperatorBuilder};

// A self-signed generator with every field the certificate needs, and the public key to check it
fn self_signed(
    oper: &dyn X509Operator,
) -> (X509V3CertificateGenerator, Box<dyn Params>, Arc<dyn Params>) {
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA").unwrap();
    // Small, since generating the primes is slow
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let (public, private) = key_gen.generate().unwrap().into_parts();

    let mut generator = X509V3CertificateGenerator::new();
    generator.set_issuer_by_str("CN=Test CA,O=Acme").unwrap();
    generator.set_subject_by_str("CN=Test CA,O=Acme").unwrap();
    generator.set_validity_days(365).unwrap();
    generator.set_subject_public_key_info(oper.spki().encode(public.as_ref()).unwrap());
    generator
        .add_basic_constraints(BasicConstraints::ca(None))
        .unwrap();
    (generator, public, private.into())
}

fn verifies(public: &dyn Params, data: &[u8], signature: &[u8]) -> bool {
    let algo = DefaultAlgoBuilder::default().build();
    let mut verifier = algo.signer().get_by_name("SHA-256withRSA").unwrap();
    verifier.init(public).unwrap();
    verifier.update(data).unwrap();
    verifier.verify_signature(signature).unwrap()
}

#[test]
fn a_self_signed_certificate_verifies_and_reads_back_as_it_was_made() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (generator, public, private) = self_signed(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    let certificate = generator.generate(factory.as_ref()).unwrap();

    assert_eq!(certificate.version(), Version::V3);
    assert_eq!(certificate.issuer().to_string(), "CN=Test CA,O=Acme");
    assert_eq!(certificate.subject().to_string(), "CN=Test CA,O=Acme");
    assert_eq!(certificate.signature_algorithm(), factory.algorithm());
    assert_eq!(certificate.extensions().unwrap().extensions().len(), 1);
    assert!(!certificate.serial_number().is_negative());
    assert!(verifies(
        public.as_ref(),
        certificate.tbs_certificate(),
        certificate.signature()
    ));

    let der = certificate
        .certificate()
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();
    let decoded = X509Certificate::decode(&der).unwrap();
    assert_eq!(decoded, certificate);
}

#[test]
fn without_a_serial_number_each_certificate_gets_a_new_random_one() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (generator, _, private) = self_signed(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    let first = generator.generate(factory.as_ref()).unwrap();
    let second = generator.generate(factory.as_ref()).unwrap();
    assert_ne!(first.serial_number(), second.serial_number());
}

#[test]
fn a_serial_number_that_is_set_is_the_one_used() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (mut generator, _, private) = self_signed(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();
    generator.set_serial_number(Asn1Integer::from(42)).unwrap();

    let certificate = generator.generate(factory.as_ref()).unwrap();
    assert_eq!(certificate.serial_number(), &Asn1Integer::from(42));
}

#[test]
fn a_missing_field_is_named() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (mut generator, _, private) = self_signed(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    generator.clear_issuer();
    let error = generator.generate(factory.as_ref()).err().unwrap();
    assert!(matches!(error, X509Error::MissingField("issuer")));

    generator.set_issuer_by_str("CN=Test CA").unwrap();
    generator.clear_subject();
    let error = generator.generate(factory.as_ref()).err().unwrap();
    assert!(matches!(error, X509Error::MissingField("subject")));
}

#[test]
fn an_end_of_the_validity_before_its_start_is_refused() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (mut generator, _, private) = self_signed(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    generator.set_not_before(tc_asn1_x509::cert::Time::new(2027, 1, 1, 0, 0, 0).unwrap());
    generator.set_not_after(tc_asn1_x509::cert::Time::new(2026, 1, 1, 0, 0, 0).unwrap());
    let error = generator.generate(factory.as_ref()).err().unwrap();
    assert!(matches!(error, X509Error::Asn1(_)));
}
