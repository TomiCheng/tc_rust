use std::sync::Arc;

use chrono::{TimeZone, Utc};
use tc_algo::Params;
use tc_asn1::{
    Asn1Any, Asn1GeneralizedTime, Asn1Integer, Asn1Oid, Decode, DecodingOptions, Encode,
    EncodingOptions,
};
use tc_asn1_cms::content::{CertificateChoices, ContentInfo, ContentType};
use tc_asn1_pkcs::SignedData;
use tc_asn1_x500::{Attribute, DirectoryString, Name};
use tc_asn1_x509::cert::Time;
use tc_asn1_x509::crl::CrlReason;
use tc_pem::{PemObject, PemWriter};
use tc_x509::cert::{
    X509AttributeCertificate, X509Certificate, X509V2AttributeCertificateGenerator,
};
use tc_x509::crl::{X509Crl, X509V2CrlGenerator};
use tc_x509::extension::key_identifier_of;
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::store::{
    X509AttrCertSelector, X509CertSelector, X509CertificateStore, X509CrlSelector, X509CrlStore,
};
use tc_x509::{DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder};

const CA: &[u8] = include_bytes!("data/crl/ca.der");
const GOOD: &[u8] = include_bytes!("data/crl/good.der");
const REVOKED: &[u8] = include_bytes!("data/crl/revoked.der");
const CRL: &[u8] = include_bytes!("data/crl/crl.der");

fn certificates() -> Vec<X509Certificate> {
    [CA, GOOD, REVOKED]
        .iter()
        .map(|der| X509Certificate::decode(der).unwrap())
        .collect()
}

fn time(year: i32, month: u32, day: u32) -> Time {
    Time::try_from(Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()).unwrap()
}

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

fn subjects<'a>(found: impl Iterator<Item = &'a X509Certificate>) -> Vec<String> {
    found.map(|c| c.subject().to_string()).collect()
}

fn signer(operator: &dyn X509Operator) -> Box<dyn tc_x509::operator::signer::SignatureFactory> {
    let mut key_gen = operator.key_pair_generator().get_by_name("RSA").unwrap();
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let private: Arc<dyn Params> = key_gen.generate().unwrap().into_parts().1.into();
    operator
        .signature_factory("SHA-256withRSA", private)
        .unwrap()
}

// X509CertSelector

#[test]
fn a_certificate_selector_with_no_criterion_selects_every_certificate() {
    let certs = certificates();
    let selector = X509CertSelector::new();
    assert_eq!(certs.iter().filter(|c| selector.matches(c)).count(), 3);
}

#[test]
fn a_certificate_selector_matches_each_criterion_it_holds() {
    let certs = certificates();
    let (ca, good) = (&certs[0], &certs[1]);
    let found = |selector: X509CertSelector| subjects(certs.iter().filter(|c| selector.matches(c)));

    let by_serial = X509CertSelector::new().with_serial_number(good.serial_number().clone());
    assert_eq!(found(by_serial), ["CN=good"]);

    let by_issuer = X509CertSelector::new().with_issuer(ca.subject().clone());
    assert_eq!(found(by_issuer).len(), 3);

    let by_subject = X509CertSelector::new().with_subject(name("CN=revoked"));
    assert_eq!(found(by_subject), ["CN=revoked"]);

    let ca_key = key_identifier_of(ca.subject_public_key_info());
    let by_ski = X509CertSelector::new().with_subject_key_identifier(ca_key);
    assert_eq!(found(by_ski), ["CN=Test CA"]);

    let by_aki = X509CertSelector::new().with_authority_key_identifier(ca_key);
    assert_eq!(found(by_aki).len(), 3);
}

#[test]
fn a_certificate_selector_compares_names_by_equivalence() {
    let certs = certificates();
    let selector = X509CertSelector::new().with_subject(name("cn=TEST   ca"));
    assert_eq!(
        subjects(certs.iter().filter(|c| selector.matches(c))),
        ["CN=Test CA"]
    );
}

#[test]
fn a_certificate_selector_by_time_takes_the_validity_with_both_ends() {
    let certs = certificates();
    let good = &certs[1];
    let count = |time: Time| {
        let selector = X509CertSelector::new().with_valid_at(time);
        certs.iter().filter(|c| selector.matches(c)).count()
    };
    assert_eq!(count(time(2026, 11, 20)), 3);
    assert_eq!(count(time(2026, 11, 1)), 0);
    assert_eq!(count(time(2027, 1, 1)), 0);
    assert!(
        X509CertSelector::new()
            .with_valid_at(good.not_before())
            .matches(good)
    );
    assert!(
        X509CertSelector::new()
            .with_valid_at(good.not_after())
            .matches(good)
    );
}

#[test]
fn every_criterion_of_a_certificate_selector_must_hold() {
    let certs = certificates();
    let selector = X509CertSelector::new()
        .with_subject(name("CN=good"))
        .with_serial_number(certs[2].serial_number().clone());
    assert!(!certs.iter().any(|c| selector.matches(c)));
}

// X509CertificateStore

#[test]
fn the_certificate_store_finds_by_serial_number_and_key_identifier_through_its_index() {
    let store: X509CertificateStore = certificates().into_iter().collect();
    let good = store.certificates()[1].clone();

    let selector = X509CertSelector::new().with_serial_number(good.serial_number().clone());
    assert_eq!(store.find(&selector), Some(&good));

    let ca_key = key_identifier_of(store.certificates()[0].subject_public_key_info());
    let selector = X509CertSelector::new().with_subject_key_identifier(ca_key);
    assert_eq!(subjects(store.select(&selector)), ["CN=Test CA"]);

    let missing = X509CertSelector::new().with_serial_number(Asn1Integer::from(42));
    assert!(store.find(&missing).is_none());
}

#[test]
fn the_certificate_store_gives_what_a_pass_gives_in_the_order_added() {
    let certs = certificates();
    let store: X509CertificateStore = certs.clone().into_iter().collect();
    for selector in [
        X509CertSelector::new(),
        X509CertSelector::new().with_issuer(name("CN=Test CA")),
        X509CertSelector::new()
            .with_issuer(name("CN=Test CA"))
            .with_serial_number(certs[2].serial_number().clone()),
    ] {
        assert_eq!(
            subjects(store.select(&selector)),
            subjects(certs.iter().filter(|c| selector.matches(c)))
        );
    }
}

#[test]
fn the_certificate_store_rebuilds_its_index_after_a_change() {
    let mut store: X509CertificateStore = certificates().into_iter().collect();
    let good = store.certificates()[1].clone();
    let selector = X509CertSelector::new().with_serial_number(good.serial_number().clone());
    assert_eq!(store.select(&selector).count(), 1);

    store.add(good.clone());
    assert_eq!(store.select(&selector).count(), 2);

    store.extend([good]);
    assert_eq!(store.select(&selector).count(), 3);
    assert_eq!(store.certificates().len(), 5);
}

// X509CrlSelector

#[test]
fn a_crl_selector_matches_any_of_its_issuers() {
    let crl = X509Crl::decode(CRL).unwrap();
    assert!(X509CrlSelector::new().matches(&crl));
    assert!(
        X509CrlSelector::new()
            .with_issuer(name("CN=Test CA"))
            .matches(&crl)
    );
    assert!(
        !X509CrlSelector::new()
            .with_issuer(name("CN=Other"))
            .matches(&crl)
    );
    assert!(
        X509CrlSelector::new()
            .with_issuer(name("CN=Other"))
            .with_issuer(name("cn=test ca"))
            .matches(&crl)
    );
}

#[test]
fn a_crl_selector_by_time_takes_the_crls_in_force() {
    let crl = X509Crl::decode(CRL).unwrap();
    let at = |time: Time| {
        X509CrlSelector::new()
            .with_date_and_time(time)
            .matches(&crl)
    };
    assert!(at(crl.this_update()));
    assert!(at(time(2026, 11, 20)));
    assert!(!at(time(2026, 11, 1)));
    assert!(!at(crl.next_update().unwrap()));
}

#[test]
fn a_crl_selector_by_crl_number_takes_the_range_with_both_ends() {
    // The test CRL is number 0x1000
    let crl = X509Crl::decode(CRL).unwrap();
    let within = |min: Option<i64>, max: Option<i64>| {
        let mut selector = X509CrlSelector::new();
        if let Some(min) = min {
            selector = selector.with_min_crl_number(Asn1Integer::from(min));
        }
        if let Some(max) = max {
            selector = selector.with_max_crl_number(Asn1Integer::from(max));
        }
        selector.matches(&crl)
    };
    assert!(within(Some(0x1000), Some(0x1000)));
    assert!(within(Some(1), None));
    assert!(within(Some(-5), None));
    assert!(!within(Some(0x1001), None));
    assert!(!within(None, Some(0xFFF)));
    assert!(!within(None, Some(-1)));
}

#[test]
fn a_crl_without_a_crl_number_is_not_selected_by_a_range() {
    let operator = DefaultX509OperatorBuilder::default().build();
    let mut generator = X509V2CrlGenerator::new();
    generator.set_issuer_by_str("CN=Test CA").unwrap();
    let crl = generator
        .generate(signer(operator.as_ref()).as_ref())
        .unwrap();
    assert!(X509CrlSelector::new().matches(&crl));
    assert!(
        !X509CrlSelector::new()
            .with_min_crl_number(Asn1Integer::from(0))
            .matches(&crl)
    );
}

// X509CrlStore

#[test]
fn the_crl_store_asks_each_crl_by_issuer_and_skips_remove_from_crl() {
    let operator = DefaultX509OperatorBuilder::default().build();
    let factory = signer(operator.as_ref());
    let good = X509Certificate::decode(GOOD).unwrap();
    let revoked = X509Certificate::decode(REVOKED).unwrap();

    // Another issuer lists the serial number of good
    let mut other = X509V2CrlGenerator::new();
    other.set_issuer_by_str("CN=Other").unwrap();
    other
        .add_crl_entry(
            good.serial_number().clone(),
            time(2026, 11, 10),
            Some(CrlReason::KeyCompromise),
        )
        .unwrap();
    let other = other.generate(factory.as_ref()).unwrap();

    // A delta of Test CA lifts a hold on good
    let mut delta = X509V2CrlGenerator::new();
    delta.set_issuer_by_str("CN=Test CA").unwrap();
    delta
        .add_crl_entry(
            good.serial_number().clone(),
            time(2026, 11, 10),
            Some(CrlReason::RemoveFromCrl),
        )
        .unwrap();
    let delta = delta.generate(factory.as_ref()).unwrap();

    let store: X509CrlStore = [other, delta, X509Crl::decode(CRL).unwrap()]
        .into_iter()
        .collect();
    assert_eq!(store.crls().len(), 3);

    assert!(store.is_revoked(&revoked));
    let (crl, entry) = store.revoked_certificate_of(&revoked).unwrap();
    assert_eq!(crl.encode().unwrap(), CRL);
    assert_eq!(entry.serial_number(), revoked.serial_number());

    assert!(!store.is_revoked(&good));
    let (crl, _) = store.revoked_certificate_of(&good).unwrap();
    assert_eq!(crl.issuer().to_string(), "CN=Test CA");
}

#[test]
fn an_empty_crl_store_revokes_nothing() {
    let store = X509CrlStore::default();
    let revoked = X509Certificate::decode(REVOKED).unwrap();
    assert!(!store.is_revoked(&revoked));
    assert!(store.revoked_certificate_of(&revoked).is_none());
}

// X509AttrCertSelector, and reading attribute certificates in every format

fn attribute_certificate(operator: &dyn X509Operator, serial: i64) -> X509AttributeCertificate {
    let role: Asn1Oid = "2.5.4.72".parse().unwrap();
    let mut generator = X509V2AttributeCertificateGenerator::new();
    generator.set_holder_by_str("CN=Alice").unwrap();
    generator.set_issuer_by_str("CN=Authority").unwrap();
    generator
        .set_serial_number(Asn1Integer::from(serial))
        .unwrap();
    generator.set_not_before(Asn1GeneralizedTime::new(2026, 11, 1, 0, 0, 0).unwrap());
    generator.set_not_after(Asn1GeneralizedTime::new(2026, 12, 1, 0, 0, 0).unwrap());
    generator
        .add_attribute(
            Attribute::new(role, vec![DirectoryString::new("operator").unwrap().into()]).unwrap(),
        )
        .unwrap();
    generator.generate(signer(operator).as_ref()).unwrap()
}

#[test]
fn an_attribute_certificate_selector_matches_serial_issuer_and_time() {
    let operator = DefaultX509OperatorBuilder::default().build();
    let certs = [
        attribute_certificate(operator.as_ref(), 1),
        attribute_certificate(operator.as_ref(), 2),
    ];
    let count =
        |selector: X509AttrCertSelector| certs.iter().filter(|c| selector.matches(c)).count();

    assert_eq!(count(X509AttrCertSelector::new()), 2);
    assert_eq!(
        count(X509AttrCertSelector::new().with_serial_number(Asn1Integer::from(2))),
        1
    );
    assert_eq!(
        count(X509AttrCertSelector::new().with_issuer(name("cn=authority"))),
        2
    );
    assert_eq!(
        count(X509AttrCertSelector::new().with_issuer(name("CN=Other"))),
        0
    );
    let at = |y, m, d| Asn1GeneralizedTime::new(y, m, d, 0, 0, 0).unwrap();
    assert_eq!(
        count(X509AttrCertSelector::new().with_valid_at(at(2026, 11, 15))),
        2
    );
    assert_eq!(
        count(X509AttrCertSelector::new().with_valid_at(at(2027, 1, 1))),
        0
    );
}

#[test]
fn attribute_certificates_read_back_from_der_pem_and_pkcs7_by_name_and_by_auto() {
    let operator = DefaultX509OperatorBuilder::default().build();
    let certificate = attribute_certificate(operator.as_ref(), 7);
    let der = certificate.encode().unwrap();

    let mut writer = PemWriter::new(Vec::new());
    writer
        .write_object(&PemObject::new("ATTRIBUTE CERTIFICATE", der.clone()))
        .unwrap();
    let pem = writer.into_inner();

    let empty = ContentInfo::new(ContentType::DATA.oid());
    let signed_data = SignedData::new(Vec::new(), empty, Vec::new()).with_certificates(vec![
        CertificateChoices::V2AttrCert(certificate.attribute_certificate().clone()),
    ]);
    let encoded = signed_data.encode_to_vec(&EncodingOptions::DER).unwrap();
    let (_, content) = Asn1Any::decode(&encoded, &DecodingOptions::default()).unwrap();
    let pkcs7 = ContentInfo::new(ContentType::SIGNED_DATA.oid())
        .with_content(content)
        .encode_to_vec(&EncodingOptions::DER)
        .unwrap();

    for (name, input) in [
        ("DER", &der),
        ("PEM", &pem),
        ("PKCS7", &pkcs7),
        ("AUTO", &der),
        ("AUTO", &pem),
        ("AUTO", &pkcs7),
    ] {
        let mut parser = operator
            .attribute_certificate_parser()
            .get_by_name(name)
            .unwrap();
        let mut source = &input[..];
        let read = parser.parse(&mut source).unwrap().expect(name);
        assert_eq!(read.encode().unwrap(), der, "{name}");
        assert!(parser.parse(&mut source).unwrap().is_none(), "{name}");
    }
}
