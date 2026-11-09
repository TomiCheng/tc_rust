use std::sync::Arc;

use chrono::{TimeDelta, TimeZone, Utc};
use tc_algo_v2::Params;
use tc_asn1::{Asn1Integer, DecodingContext, DecodingOptions};
use tc_asn1_x509::cert::{Time, Version};
use tc_asn1_x509::crl::CrlReason;
use tc_asn1_x509::ext::ExtensionId;
use tc_x509::cert::{X509Certificate, X509V3CertificateGenerator};
use tc_x509::crl::{X509Crl, X509V2CrlGenerator};
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509Operator, X509OperatorBuilder};

// Made with openssl, with a subjectKeyIdentifier
const OPENSSL_CA: &[u8] = include_bytes!("data/crl/ca.der");

fn keys(oper: &dyn X509Operator) -> (Arc<dyn Params>, Arc<dyn Params>) {
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA").unwrap();
    // Small, since generating the primes is slow
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let (public, private) = key_gen.generate().unwrap().into_parts();
    (public.into(), private.into())
}

fn ca_certificate(
    oper: &dyn X509Operator,
    keys: &(Arc<dyn Params>, Arc<dyn Params>),
) -> X509Certificate {
    let mut generator = X509V3CertificateGenerator::new();
    generator.set_issuer_by_str("CN=Test CA").unwrap();
    generator.set_subject_by_str("CN=Test CA").unwrap();
    generator.set_validity_days(30).unwrap();
    generator.set_subject_public_key_info(oper.spki().encode(keys.0.as_ref()).unwrap());
    let signer = oper
        .signature_factory("SHA-256withRSA", keys.1.clone())
        .unwrap();
    generator.generate(signer.as_ref()).unwrap()
}

fn time(hour: u32) -> Time {
    Time::try_from(Utc.with_ymd_and_hms(2026, 11, 9, hour, 0, 0).unwrap()).unwrap()
}

#[test]
fn a_crl_from_the_ca_verifies_and_lists_its_entries() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let keys = keys(oper.as_ref());
    let ca = ca_certificate(oper.as_ref(), &keys);
    let factory = oper
        .signature_factory("SHA-256withRSA", keys.1.clone())
        .unwrap();

    let mut generator = X509V2CrlGenerator::new();
    generator.set_issuer_by_certificate(&ca);
    generator.set_this_update(time(1));
    generator.set_next_update(time(7));
    generator
        .add_crl_entry(
            Asn1Integer::from(1),
            time(0),
            Some(CrlReason::KeyCompromise),
        )
        .unwrap();
    generator
        .add_crl_entry(Asn1Integer::from(2), time(0), None)
        .unwrap();
    let crl = generator.generate(factory.as_ref()).unwrap();

    assert_eq!(crl.version(), Version::V2);
    assert!(crl.issuer().equivalent(ca.subject()));
    assert_eq!(crl.this_update(), time(1));
    assert_eq!(crl.next_update(), Some(time(7)));
    assert_eq!(crl.signature_algorithm(), factory.algorithm());
    crl.verify(oper.verifier_factory_provider(keys.0.clone()).as_ref())
        .unwrap();

    let entries = crl.revoked_certificates();
    assert_eq!(entries.len(), 2);
    let mut context = DecodingContext::new(DecodingOptions::default());
    let reason = entries[0]
        .extensions()
        .unwrap()
        .get_crl_reason(&mut context)
        .unwrap();
    assert_eq!(reason, Some(CrlReason::KeyCompromise));
    assert!(entries[1].extensions().is_none());

    let decoded = X509Crl::decode(&crl.encode().unwrap()).unwrap();
    assert_eq!(decoded, crl);
}

#[test]
fn only_the_issuer_is_required_and_the_this_update_defaults_to_now() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (_, private) = keys(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    let mut generator = X509V2CrlGenerator::new();
    let error = generator.generate(factory.as_ref()).err().unwrap();
    assert!(matches!(error, X509Error::MissingField("issuer")));

    generator.set_issuer_by_str("CN=Test CA").unwrap();
    let before = Time::try_from(Utc::now() - TimeDelta::seconds(1)).unwrap();
    let crl = generator.generate(factory.as_ref()).unwrap();
    let after = Time::try_from(Utc::now() + TimeDelta::seconds(1)).unwrap();
    assert!(before <= crl.this_update() && crl.this_update() <= after);
    assert_eq!(crl.next_update(), None);
    assert!(crl.revoked_certificates().is_empty());
    assert!(crl.extensions().is_none());
}

#[test]
fn the_next_update_after_a_span_counts_from_the_this_update() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (_, private) = keys(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    let mut generator = X509V2CrlGenerator::new();
    generator.set_issuer_by_str("CN=Test CA").unwrap();
    generator.set_this_update(time(1));
    generator.set_next_update_after(TimeDelta::hours(6));
    let crl = generator.generate(factory.as_ref()).unwrap();
    assert_eq!(crl.next_update(), Some(time(7)));

    generator.clear_next_update();
    let crl = generator.generate(factory.as_ref()).unwrap();
    assert_eq!(crl.next_update(), None);
}

#[test]
fn entries_can_be_removed_and_cleared() {
    let mut generator = X509V2CrlGenerator::new();
    generator
        .add_crl_entry(Asn1Integer::from(1), time(0), None)
        .unwrap();
    generator
        .add_crl_entry(Asn1Integer::from(2), time(0), None)
        .unwrap();

    assert!(generator.remove_crl_entry(&Asn1Integer::from(1)));
    assert!(!generator.remove_crl_entry(&Asn1Integer::from(1)));
    generator.clear_crl_entries();
    assert!(!generator.remove_crl_entry(&Asn1Integer::from(2)));
}

#[test]
fn the_crl_number_and_authority_key_identifier_come_from_their_helpers() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (_, private) = keys(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();
    let ca = X509Certificate::decode(OPENSSL_CA).unwrap();

    let mut generator = X509V2CrlGenerator::new();
    generator.set_issuer_by_certificate(&ca);
    generator.add_crl_number(4096).unwrap();
    generator.add_authority_key_identifier(&ca).unwrap();
    let crl = generator.generate(factory.as_ref()).unwrap();

    let mut context = DecodingContext::new(DecodingOptions::default());
    let extensions = crl.extensions().unwrap();
    assert!(!extensions.get(ExtensionId::CRL_NUMBER).unwrap().critical());
    let authority = extensions
        .get_authority_key_identifier(&mut context)
        .unwrap()
        .unwrap();
    let subject = ca
        .extensions()
        .unwrap()
        .get_subject_key_identifier(&mut context)
        .unwrap()
        .unwrap();
    assert_eq!(authority.key_identifier(), Some(subject.key_identifier()));
}

#[test]
fn an_extension_can_be_added_only_once() {
    let mut generator = X509V2CrlGenerator::new();
    generator.add_crl_number(1).unwrap();
    let error = generator.add_crl_number(2).err().unwrap();
    assert!(matches!(error, X509Error::DuplicateExtension));

    assert!(generator.remove_extension(&ExtensionId::CRL_NUMBER.into()));
    generator.add_crl_number(2).unwrap();
}

#[test]
fn a_ca_without_a_subject_key_identifier_cannot_give_an_authority_key_identifier() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let keys = keys(oper.as_ref());
    let ca = ca_certificate(oper.as_ref(), &keys);

    let mut generator = X509V2CrlGenerator::new();
    let error = generator.add_authority_key_identifier(&ca).err().unwrap();
    assert!(matches!(
        error,
        X509Error::MissingExtension("subjectKeyIdentifier")
    ));
}

#[test]
fn an_entry_keeps_the_extensions_it_is_given() {
    use tc_asn1_x509::ext::{Extension, Extensions};
    use tc_asn1_x509::name::{GeneralName, GeneralNames};

    let oper = DefaultX509OperatorBuilder::default().build();
    let (_, private) = keys(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();
    let other = GeneralNames::new(vec![GeneralName::DirectoryName(
        "CN=Other CA".parse().unwrap(),
    )])
    .unwrap();
    let extensions = Extensions::new(vec![
        Extension::with_value(ExtensionId::CRL_REASONS, false, &CrlReason::Superseded).unwrap(),
        Extension::with_value(ExtensionId::CERTIFICATE_ISSUER, true, &other).unwrap(),
    ])
    .unwrap();

    let mut generator = X509V2CrlGenerator::new();
    generator.set_issuer_by_str("CN=Test CA").unwrap();
    generator.add_crl_entry_with_extensions(Asn1Integer::from(7), time(0), extensions.clone());
    let crl = generator.generate(factory.as_ref()).unwrap();

    let entries = crl.revoked_certificates();
    assert_eq!(entries[0].serial_number(), &Asn1Integer::from(7));
    assert_eq!(entries[0].extensions(), Some(&extensions));
}

#[test]
fn a_template_crl_gives_its_fields_and_add_crl_carries_its_entries() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let (_, private) = keys(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();

    let mut generator = X509V2CrlGenerator::new();
    generator.set_issuer_by_str("CN=Test CA").unwrap();
    generator.set_this_update(time(1));
    generator.set_next_update(time(7));
    generator
        .add_crl_entry(
            Asn1Integer::from(1),
            time(0),
            Some(CrlReason::KeyCompromise),
        )
        .unwrap();
    generator.add_crl_number(1).unwrap();
    let first = generator.generate(factory.as_ref()).unwrap();

    // The same CRL again from the template
    let again = X509V2CrlGenerator::from_crl(&first)
        .generate(factory.as_ref())
        .unwrap();
    assert_eq!(again.tbs_cert_list(), first.tbs_cert_list());

    // The next CRL: its own dates and number, the last entries and a new one
    let mut next = X509V2CrlGenerator::new();
    next.set_issuer(first.issuer().clone());
    next.set_this_update(time(7));
    next.add_crl(&first);
    next.add_crl_entry(Asn1Integer::from(2), time(6), None)
        .unwrap();
    next.add_crl_number(2).unwrap();
    let next = next.generate(factory.as_ref()).unwrap();
    let serials: Vec<_> = next
        .revoked_certificates()
        .iter()
        .map(|entry| entry.serial_number().clone())
        .collect();
    assert_eq!(serials, [Asn1Integer::from(1), Asn1Integer::from(2)]);
    assert_eq!(
        next.revoked_certificates()[0].extensions(),
        first.revoked_certificates()[0].extensions()
    );
}

#[test]
fn reset_clears_every_field() {
    let mut generator = X509V2CrlGenerator::new();
    generator.set_issuer_by_str("CN=Test CA").unwrap();
    generator.add_crl_number(1).unwrap();
    generator.reset();

    let oper = DefaultX509OperatorBuilder::default().build();
    let (_, private) = keys(oper.as_ref());
    let factory = oper.signature_factory("SHA-256withRSA", private).unwrap();
    let error = generator.generate(factory.as_ref()).err().unwrap();
    assert!(matches!(error, X509Error::MissingField("issuer")));
    generator.add_crl_number(1).unwrap();
}
