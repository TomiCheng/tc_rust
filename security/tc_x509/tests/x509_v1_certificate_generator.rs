use std::sync::Arc;

use tc_algo::Params;
use tc_asn1_x509::cert::Version;
use tc_x509::cert::{X509Certificate, X509V1CertificateGenerator};
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509Operator, X509OperatorBuilder};

fn keys(oper: &dyn X509Operator) -> (Arc<dyn Params>, Arc<dyn Params>) {
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA").unwrap();
    // Small, since generating the primes is slow
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let (public, private) = key_gen.generate().unwrap().into_parts();
    (public.into(), private.into())
}

fn filled(oper: &dyn X509Operator, public: &dyn Params) -> X509V1CertificateGenerator {
    let mut generator = X509V1CertificateGenerator::new();
    generator.set_issuer_by_str("CN=Test CA").unwrap();
    generator.set_subject_by_str("CN=Test CA").unwrap();
    generator.set_validity_days(30).unwrap();
    generator.set_subject_public_key_info(oper.spki().encode(public).unwrap());
    generator
}

#[test]
fn a_version_1_certificate_has_no_extensions_and_verifies_after_a_round_trip() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (public, private) = keys(oper.as_ref());
    let generator = filled(oper.as_ref(), public.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    let certificate = generator.generate(factory.as_ref()).unwrap();
    assert_eq!(certificate.version(), Version::V1);
    assert!(certificate.extensions().is_none());
    assert_eq!(certificate.subject().to_string(), "CN=Test CA");

    let decoded = X509Certificate::decode(&certificate.encode().unwrap()).unwrap();
    assert_eq!(decoded, certificate);
    let provider = oper.verifier_factory_provider(public);
    decoded.verify(provider.as_ref()).unwrap();
}

#[test]
fn a_version_1_certificate_cannot_leave_out_its_subject() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (public, private) = keys(oper.as_ref());
    let mut generator = filled(oper.as_ref(), public.as_ref());
    generator.clear_subject();
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    let error = generator.generate(factory.as_ref()).err().unwrap();
    assert!(matches!(error, X509Error::MissingField("subject")));
}

#[test]
fn a_serial_number_that_is_not_positive_is_refused() {
    let mut generator = X509V1CertificateGenerator::new();
    let error = generator
        .set_serial_number(tc_asn1::Asn1Integer::from(0))
        .err()
        .unwrap();
    assert!(matches!(error, X509Error::InvalidSerialNumber));
}
