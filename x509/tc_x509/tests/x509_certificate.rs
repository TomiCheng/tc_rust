use tc_asn1::Asn1Error;
use tc_asn1_x509::cert::{Time, Version};
use tc_x509::cert::X509Certificate;

const RFC_8410: &[u8] = include_bytes!("data/rfc8410.der");

#[test]
fn the_rfc_8410_certificate_exposes_its_fields() {
    let certificate = X509Certificate::decode(RFC_8410).unwrap();
    assert_eq!(certificate.version(), Version::V3);
    assert_eq!(certificate.issuer().to_string(), "CN=IETF Test Demo");
    assert_eq!(certificate.subject().to_string(), "CN=IETF Test Demo");
    assert_eq!(
        certificate.not_before(),
        Time::new(2016, 8, 1, 12, 19, 24).unwrap()
    );
    assert_eq!(certificate.not_after().year(), 2040);
    assert_eq!(certificate.signature_algorithm().to_string(), "1.3.101.112");
    assert_eq!(certificate.tbs_certificate(), &RFC_8410[4..230]);
    assert_eq!(certificate.signature(), &RFC_8410[240..]);
    assert!(certificate.issuer_unique_id().is_none());
    assert_eq!(certificate.extensions().unwrap().extensions().len(), 3);
}

#[test]
fn validity_includes_both_ends_of_the_period() {
    let certificate = X509Certificate::decode(RFC_8410).unwrap();
    assert!(certificate.is_valid_at(&certificate.not_before()));
    assert!(certificate.is_valid_at(&certificate.not_after()));
    assert!(certificate.is_valid_at(&Time::new(2026, 10, 21, 0, 0, 0).unwrap()));
    assert!(!certificate.is_valid_at(&Time::new(2016, 8, 1, 12, 19, 23).unwrap()));
    assert!(!certificate.is_valid_at(&Time::new(2041, 1, 1, 0, 0, 0).unwrap()));
}

#[test]
fn trailing_bytes_after_the_certificate_are_rejected() {
    let mut bytes = RFC_8410.to_vec();
    bytes.push(0);
    assert_eq!(
        X509Certificate::decode(&bytes),
        Err(Asn1Error::TrailingData)
    );
}
