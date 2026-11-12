use tc_asn1::{DecodingContext, DecodingOptions};
use tc_asn1_x509::ext::{Extensions, ExtensionId};
use tc_x509::cert::X509Certificate;
use tc_x509::extension::{authority_key_identifier, key_identifier_of, subject_key_identifier};

const CA: &[u8] = include_bytes!("data/crl/ca.der");
const GOOD: &[u8] = include_bytes!("data/crl/good.der");

fn single(extension: tc_asn1_x509::ext::Extension) -> Extensions {
    Extensions::new(vec![extension]).unwrap()
}

#[test]
fn the_key_identifier_of_a_public_key_is_the_one_openssl_wrote() {
    let ca = X509Certificate::decode(CA).unwrap();
    let mut context = DecodingContext::new(DecodingOptions::default());
    let written = ca
        .extensions()
        .unwrap()
        .get_subject_key_identifier(&mut context)
        .unwrap()
        .unwrap();
    assert_eq!(
        key_identifier_of(ca.subject_public_key_info()),
        written.key_identifier()
    );

    let extension = subject_key_identifier(ca.subject_public_key_info()).unwrap();
    assert!(!extension.critical());
    let made = single(extension)
        .get_subject_key_identifier(&mut context)
        .unwrap()
        .unwrap();
    assert_eq!(made.key_identifier(), written.key_identifier());
}

#[test]
fn the_authority_key_identifier_of_a_certificate_is_the_one_openssl_wrote() {
    let ca = X509Certificate::decode(CA).unwrap();
    let good = X509Certificate::decode(GOOD).unwrap();
    let mut context = DecodingContext::new(DecodingOptions::default());
    let written = good
        .extensions()
        .unwrap()
        .get_authority_key_identifier(&mut context)
        .unwrap()
        .unwrap();

    let extension = authority_key_identifier(&ca).unwrap();
    assert!(!extension.critical());
    assert_eq!(extension.extn_id(), &ExtensionId::AUTHORITY_KEY_IDENTIFIER.oid());
    let made = single(extension)
        .get_authority_key_identifier(&mut context)
        .unwrap()
        .unwrap();
    assert_eq!(made.key_identifier(), written.key_identifier());
}
