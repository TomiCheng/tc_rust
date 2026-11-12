use std::sync::Arc;

use tc_algo::Params;
use tc_asn1::Asn1Oid;
use tc_asn1_x500::{Attribute, DirectoryString};
use tc_x509::cert::{
    X509AttributeCertificate, X509V2AttributeCertificateGenerator, X509V3CertificateGenerator,
};
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509Operator, X509OperatorBuilder};

fn keys(oper: &dyn X509Operator) -> (Arc<dyn Params>, Arc<dyn Params>) {
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA").unwrap();
    // Small, since generating the primes is slow
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let (public, private) = key_gen.generate().unwrap().into_parts();
    (public.into(), private.into())
}

fn role(name: &str) -> Attribute {
    let oid: Asn1Oid = "1.2.3.4".parse().unwrap();
    Attribute::new(oid, vec![DirectoryString::new(name).unwrap().into()]).unwrap()
}

fn filled(oper: &dyn X509Operator) -> X509V2AttributeCertificateGenerator {
    let (public, private) = keys(oper);
    let mut holder = X509V3CertificateGenerator::new();
    holder.set_issuer_by_str("CN=Alice").unwrap();
    holder.set_subject_by_str("CN=Alice").unwrap();
    holder.set_validity_days(30).unwrap();
    holder.set_subject_public_key_info(oper.spki().encode(public.as_ref()).unwrap());
    let signer = oper.signature_factory("SHA-256withRSA", private).unwrap();
    let holder = holder.generate(signer.as_ref()).unwrap();

    let mut generator = X509V2AttributeCertificateGenerator::new();
    generator.set_holder_by_certificate(&holder).unwrap();
    generator.set_issuer_by_str("CN=My AA").unwrap();
    generator.set_validity_days(30).unwrap();
    generator.add_attribute(role("admin")).unwrap();
    generator
}

#[test]
fn an_attribute_certificate_verifies_with_the_authority_key_after_a_round_trip() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let generator = filled(oper.as_ref());
    let (public, private) = keys(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    let certificate = generator.generate(factory.as_ref()).unwrap();
    let decoded = X509AttributeCertificate::decode(&certificate.encode().unwrap()).unwrap();
    assert_eq!(decoded, certificate);

    let holder = decoded.holder().base_certificate_id().unwrap();
    assert!(!holder.serial().as_bytes().is_empty());
    assert_eq!(decoded.attributes().len(), 1);
    assert!(decoded.attribute(&"1.2.3.4".parse().unwrap()).is_some());
    assert!(decoded.is_valid_at(decoded.not_before()));

    let provider = oper.verifier_factory_provider(public);
    decoded.verify(provider.as_ref()).unwrap();
}

#[test]
fn an_attribute_certificate_does_not_verify_with_another_key() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let generator = filled(oper.as_ref());
    let (_, private) = keys(oper.as_ref());
    let (other, _) = keys(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();
    let certificate = generator.generate(factory.as_ref()).unwrap();

    let provider = oper.verifier_factory_provider(other);
    let error = certificate.verify(provider.as_ref()).err().unwrap();
    assert!(matches!(error, X509Error::InvalidSignature));
}

#[test]
fn an_attribute_certificate_needs_at_least_one_attribute() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let mut generator = filled(oper.as_ref());
    generator.clear_attributes();
    let (_, private) = keys(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    let error = generator.generate(factory.as_ref()).err().unwrap();
    assert!(matches!(error, X509Error::MissingField("attributes")));
}

#[test]
fn an_attribute_type_can_be_added_only_once() {
    let mut generator = X509V2AttributeCertificateGenerator::new();
    generator.add_attribute(role("admin")).unwrap();
    let error = generator.add_attribute(role("user")).err().unwrap();
    assert!(matches!(error, X509Error::DuplicateAttribute));

    assert!(generator.remove_attribute(&"1.2.3.4".parse().unwrap()));
    generator.add_attribute(role("user")).unwrap();
}
