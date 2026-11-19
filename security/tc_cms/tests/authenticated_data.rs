use std::sync::Arc;

use tc_algo::Params;
use tc_algo::params::key::KeyOwned;
use tc_asn1::{Asn1OctetString, Decode, DecodingOptions, tag};
use tc_asn1_cms::content::{AuthenticatedData, ContentInfo};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_cms::authenticated::{CmsAuthenticatedData, CmsAuthenticatedDataGenerator};
use tc_cms::enveloped::{
    KekRecipientInfoGenerator, KeyTransRecipientInfoGenerator, PasswordKey,
    PasswordRecipientInfoGenerator,
};
use tc_cms::{CmsError, CmsOperatorBuilder, DefaultCmsOperatorBuilder};
use tc_pkcs::{DefaultPkcsOperatorBuilder, PkcsOperatorBuilder};
use tc_x509::cert::X509Certificate;

const CONTENT: &[u8] = include_bytes!("data/cms_content.txt");
const HMAC_SHA256: &str = "1.2.840.113549.2.9";
const HMAC_SHA512: &str = "1.2.840.113549.2.11";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";

fn rsa_key() -> Arc<dyn Params> {
    let der = include_bytes!("data/env_recipient_key.der");
    let info = PrivateKeyInfo::decode(der, &DecodingOptions::default())
        .unwrap()
        .1;
    let pkcs = DefaultPkcsOperatorBuilder::default().build();
    Arc::from(pkcs.private_key_info().decode(&info).unwrap())
}

fn generator(digest: Option<&str>) -> CmsAuthenticatedDataGenerator {
    let mut generator = CmsAuthenticatedDataGenerator::new();
    let certificate = X509Certificate::decode(include_bytes!("data/env_recipient.der")).unwrap();
    generator.add_recipient(KeyTransRecipientInfoGenerator::new(&certificate));
    generator.add_recipient(KekRecipientInfoGenerator::new(b"kek", &[9; 32]));
    generator.add_recipient(PasswordRecipientInfoGenerator::new(
        "correct horse",
        "2.16.840.1.101.3.4.1.2".parse().unwrap(),
        vec![7; 16],
        1000,
    ));
    if let Some(digest) = digest {
        generator.set_digest_algorithm(digest.parse().unwrap());
    }
    generator
}

fn keys() -> [Arc<dyn Params>; 3] {
    [
        rsa_key(),
        Arc::new(KeyOwned::new(vec![9; 32])),
        Arc::new(PasswordKey::new("correct horse")),
    ]
}

#[test]
fn each_recipient_verifies_the_mac_with_and_without_authenticated_attributes() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    for (mac, digest) in [(HMAC_SHA256, None), (HMAC_SHA512, Some(SHA256))] {
        let data = oper
            .authenticated_data()
            .generate(&generator(digest), CONTENT, &mac.parse().unwrap())
            .unwrap();
        let data = CmsAuthenticatedData::decode(&data.encode().unwrap()).unwrap();
        assert_eq!(data.auth_attributes().is_some(), digest.is_some());
        for (recipient, key) in data.recipient_infos().iter().zip(keys()) {
            let content = oper
                .authenticated_data()
                .verify(&data, recipient, key.as_ref())
                .unwrap();
            assert_eq!(content, CONTENT, "{mac}");
        }
    }
}

// 換掉封裝的內容，其他欄位不動
fn with_content(data: &CmsAuthenticatedData, content: &[u8]) -> CmsAuthenticatedData {
    let inner = data.authenticated_data();
    let encapsulated = ContentInfo::new(data.content_type().clone())
        .with_content(tc_asn1::Asn1Any::primitive(tag::OCTET_STRING, content));
    let mut changed = AuthenticatedData::new(
        inner.recipient_infos().to_vec(),
        inner.mac_algorithm().clone(),
        encapsulated,
        Asn1OctetString::new(data.mac()),
    );
    if let (Some(digest), Some(attributes)) = (inner.digest_algorithm(), inner.auth_attrs()) {
        changed = changed
            .with_digest_algorithm(digest.clone())
            .with_auth_attrs(attributes.to_vec());
    }
    CmsAuthenticatedData::new(changed)
}

#[test]
fn a_changed_content_does_not_verify() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    for digest in [None, Some(SHA256)] {
        let data = oper
            .authenticated_data()
            .generate(&generator(digest), CONTENT, &HMAC_SHA256.parse().unwrap())
            .unwrap();
        let changed = with_content(&data, b"hello CMS");
        let recipient = &changed.recipient_infos()[1];
        let error = oper
            .authenticated_data()
            .verify(&changed, recipient, &KeyOwned::new(vec![9; 32]))
            .unwrap_err();
        let expected = match digest {
            None => matches!(error, CmsError::MacMismatch),
            Some(_) => matches!(error, CmsError::MessageDigestMismatch),
        };
        assert!(expected, "{error}");
    }
}
