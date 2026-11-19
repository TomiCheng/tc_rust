use tc_algo::params::key::KeyOwned;
use tc_asn1::{Asn1Object, Asn1OctetString};
use tc_asn1_x500::{Attribute, AttributeValue};
use tc_cms::encrypted::CmsEncryptedData;
use tc_cms::{CmsError, CmsOperatorBuilder, DefaultCmsOperatorBuilder};

const CONTENT: &[u8] = include_bytes!("data/cms_content.txt");
const EX_CONTENT: &[u8] = include_bytes!("data/rfc4134/ExContent.bin");
const AES128: &str = "2.16.840.1.101.3.4.1.2";
const AES256: &str = "2.16.840.1.101.3.4.1.42";

// RFC 4134 section 7: the TripleDES key of 7.1 and 7.2
const RFC4134_KEY: [u8; 24] = [
    0x73, 0x7c, 0x79, 0x1f, 0x25, 0xea, 0xd0, 0xe0, 0x46, 0x29, 0x25, 0x43, 0x52, 0xf7, 0xdc, 0x62,
    0x91, 0xe5, 0xcb, 0x26, 0x91, 0x7a, 0xda, 0x32,
];

#[test]
fn the_rfc_4134_examples_decrypt_with_their_key() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let key = KeyOwned::new(RFC4134_KEY.to_vec());
    let simple = CmsEncryptedData::decode(include_bytes!("data/rfc4134/7.1.bin")).unwrap();
    assert!(simple.unprotected_attributes().is_none());
    let content = oper.encrypted_data().decrypt(&simple, &key).unwrap();
    assert_eq!(content.as_slice(), EX_CONTENT);

    let attributed = CmsEncryptedData::decode(include_bytes!("data/rfc4134/7.2.bin")).unwrap();
    assert_eq!(attributed.unprotected_attributes().unwrap().len(), 1);
    let content = oper.encrypted_data().decrypt(&attributed, &key).unwrap();
    assert_eq!(content.as_slice(), EX_CONTENT);
}

#[test]
fn what_openssl_encrypted_decrypts() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let data = CmsEncryptedData::decode(include_bytes!("data/encrypted_aes128.der")).unwrap();
    let key = KeyOwned::new((0..16).collect());
    let content = oper.encrypted_data().decrypt(&data, &key).unwrap();
    assert_eq!(content.as_slice(), CONTENT);
}

#[test]
fn what_is_encrypted_here_decrypts_and_a_key_of_the_wrong_length_is_refused() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let key = KeyOwned::new(vec![5; 32]);
    let label = Attribute::new(
        "1.2.3.4".parse::<tc_asn1::Asn1Oid>().unwrap(),
        vec![AttributeValue::Other(Asn1Object::OctetString(
            Asn1OctetString::new(b"label"),
        ))],
    )
    .unwrap();
    let data = oper
        .encrypted_data()
        .generate(CONTENT, &AES256.parse().unwrap(), &key, vec![label])
        .unwrap();
    let data = CmsEncryptedData::decode(&data.encode().unwrap()).unwrap();
    assert_eq!(data.unprotected_attributes().unwrap().len(), 1);
    let content = oper.encrypted_data().decrypt(&data, &key).unwrap();
    assert_eq!(content.as_slice(), CONTENT);

    let result =
        oper.encrypted_data()
            .generate(CONTENT, &AES128.parse().unwrap(), &key, Vec::new());
    assert!(matches!(result, Err(CmsError::InvalidKey)));
}
