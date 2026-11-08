use chrono::{TimeZone, Utc};
use tc_asn1::Asn1Integer;
use tc_asn1_x509::ext::{BasicConstraints, Extension, ExtensionId, KeyUsage};
use tc_asn1_x509::name::{GeneralName, GeneralNames};
use tc_x509::X509Error;
use tc_x509::cert::{X509Certificate, X509V3CertificateGenerator};

#[test]
fn a_serial_number_must_be_a_positive_integer() {
    let mut generator = X509V3CertificateGenerator::new();

    assert!(generator.set_serial_number(Asn1Integer::from(1)).is_ok());
    for bad in [0, -1] {
        let error = generator
            .set_serial_number(Asn1Integer::from(bad))
            .unwrap_err();
        assert!(matches!(error, X509Error::InvalidSerialNumber));
    }
}

#[test]
fn names_are_read_from_strings_and_a_malformed_one_is_an_asn1_error() {
    let mut generator = X509V3CertificateGenerator::new();

    assert!(generator.set_issuer_by_str("CN=My CA,O=Acme").is_ok());
    assert!(generator.set_subject_by_str("CN=Alice,O=Acme").is_ok());

    let error = generator.set_issuer_by_str("CN").unwrap_err();
    assert!(matches!(error, X509Error::Asn1(_)));
    let error = generator.set_subject_by_str("CN").unwrap_err();
    assert!(matches!(error, X509Error::Asn1(_)));
}

#[test]
fn a_validity_in_days_must_end_before_the_year_10000() {
    let mut generator = X509V3CertificateGenerator::new();

    assert!(generator.set_validity_days(365).is_ok());
    let error = generator.set_validity_days(u32::MAX).unwrap_err();
    assert!(matches!(error, X509Error::Asn1(_)));
}

#[test]
fn a_datetime_must_fall_within_1950_to_9999() {
    let mut generator = X509V3CertificateGenerator::new();
    let in_range = Utc.with_ymd_and_hms(2026, 11, 8, 0, 0, 0).unwrap();
    let too_early = Utc.with_ymd_and_hms(1949, 12, 31, 23, 59, 59).unwrap();

    assert!(generator.set_not_before_by_datetime(in_range).is_ok());
    assert!(generator.set_not_after_by_datetime(in_range).is_ok());

    let error = generator.set_not_before_by_datetime(too_early).unwrap_err();
    assert!(matches!(error, X509Error::Asn1(_)));
    let error = generator.set_not_after_by_datetime(too_early).unwrap_err();
    assert!(matches!(error, X509Error::Asn1(_)));
}

#[test]
fn a_validity_from_datetimes_must_not_end_before_it_starts() {
    let mut generator = X509V3CertificateGenerator::new();
    let start = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();

    assert!(generator.set_validity_by_datetime(start, end).is_ok());
    let error = generator.set_validity_by_datetime(end, start).unwrap_err();
    assert!(matches!(error, X509Error::Asn1(_)));
}

#[test]
fn removing_an_extension_reports_whether_it_was_there() {
    let mut generator = X509V3CertificateGenerator::new();
    let basic_constraints: tc_asn1::Asn1Oid = "2.5.29.19".parse().unwrap();
    let key_usage: tc_asn1::Asn1Oid = "2.5.29.15".parse().unwrap();
    generator
        .add_extension(Extension::new(
            basic_constraints.clone(),
            true,
            &[0x30, 0x00],
        ))
        .unwrap();

    assert!(!generator.remove_extension(&key_usage));
    assert!(generator.remove_extension(&basic_constraints));
    assert!(!generator.remove_extension(&basic_constraints));
}

#[test]
fn an_extension_can_be_added_once_and_replaced_after_it_is_removed() {
    let mut generator = X509V3CertificateGenerator::new();
    let basic_constraints: tc_asn1::Asn1Oid = "2.5.29.19".parse().unwrap();
    let extension = Extension::new(basic_constraints.clone(), true, &[0x30, 0x00]);

    generator.add_extension(extension.clone()).unwrap();
    let error = generator.add_extension(extension.clone()).unwrap_err();
    assert!(matches!(error, X509Error::DuplicateExtension));

    generator.remove_extension(&basic_constraints);
    assert!(generator.add_extension(extension).is_ok());
}

#[test]
fn the_common_extensions_are_added_once_each() {
    let mut generator = X509V3CertificateGenerator::new();
    let names = GeneralNames::new(vec![GeneralName::dns_name("example.com").unwrap()]).unwrap();

    generator
        .add_basic_constraints(BasicConstraints::ca(None))
        .unwrap();
    generator
        .add_key_usage(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN)
        .unwrap();
    generator.add_subject_alt_name(names.clone()).unwrap();

    let error = generator
        .add_basic_constraints(BasicConstraints::end_entity())
        .unwrap_err();
    assert!(matches!(error, X509Error::DuplicateExtension));
    let error = generator.add_key_usage(KeyUsage::CRL_SIGN).unwrap_err();
    assert!(matches!(error, X509Error::DuplicateExtension));
    let error = generator.add_subject_alt_name(names).unwrap_err();
    assert!(matches!(error, X509Error::DuplicateExtension));

    assert!(generator.remove_extension(&ExtensionId::BASIC_CONSTRAINTS.oid()));
    assert!(generator.remove_extension(&ExtensionId::KEY_USAGE.oid()));
    assert!(generator.remove_extension(&ExtensionId::SUBJECT_ALT_NAME.oid()));
}

#[test]
fn dns_names_become_one_subject_alt_name_and_an_empty_list_is_refused() {
    let mut generator = X509V3CertificateGenerator::new();

    let error = generator.add_subject_alt_name_dns(&[]).unwrap_err();
    assert!(matches!(error, X509Error::Asn1(_)));

    generator
        .add_subject_alt_name_dns(&["example.com", "www.example.com"])
        .unwrap();
    let error = generator
        .add_subject_alt_name_dns(&["other.example.com"])
        .unwrap_err();
    assert!(matches!(error, X509Error::DuplicateExtension));
}

#[test]
fn reset_clears_the_extensions_so_they_can_be_added_again() {
    let mut generator = X509V3CertificateGenerator::new();
    generator.set_issuer_by_str("CN=My CA").unwrap();
    generator
        .add_subject_alt_name_dns(&["example.com"])
        .unwrap();

    generator.reset();

    assert!(!generator.remove_extension(&ExtensionId::SUBJECT_ALT_NAME.oid()));
    assert!(generator.add_subject_alt_name_dns(&["example.com"]).is_ok());
}

const RFC_8410: &[u8] = include_bytes!("data/rfc8410.der");

#[test]
fn a_template_brings_its_extensions_so_they_cannot_be_added_again() {
    let template = X509Certificate::decode(RFC_8410).unwrap();
    let mut generator = X509V3CertificateGenerator::from_x509_certificate(&template);

    let error = generator
        .add_basic_constraints(BasicConstraints::end_entity())
        .unwrap_err();
    assert!(matches!(error, X509Error::DuplicateExtension));
    assert!(generator.remove_extension(&ExtensionId::KEY_USAGE.oid()));
    assert!(generator.remove_extension(&ExtensionId::SUBJECT_KEY_IDENTIFIER.oid()));
    assert!(!generator.remove_extension(&ExtensionId::SUBJECT_ALT_NAME.oid()));
}
