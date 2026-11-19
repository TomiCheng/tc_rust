use std::sync::Arc;

use tc_algo::Params;
use tc_algo::params::key::KeyOwned;
use tc_asn1::{Asn1Object, Asn1OctetString, Decode, DecodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x500::{Attribute, AttributeValue};
use tc_cms::auth_enveloped::{CmsAuthEnvelopedData, CmsAuthEnvelopedDataGenerator};
use tc_cms::enveloped::{
    KekRecipientInfoGenerator, KeyAgreeKey, KeyTransRecipientInfoGenerator, PasswordKey,
    PasswordRecipientInfoGenerator,
};
use tc_cms::{CmsOperatorBuilder, DefaultCmsOperatorBuilder};
use tc_pkcs::{DefaultPkcsOperatorBuilder, PkcsOperatorBuilder};
use tc_x509::cert::X509Certificate;

const CONTENT: &[u8] = include_bytes!("data/cms_content.txt");
const AES128_GCM: &str = "2.16.840.1.101.3.4.1.6";
const AES256_GCM: &str = "2.16.840.1.101.3.4.1.46";
const AES192_CCM: &str = "2.16.840.1.101.3.4.1.27";

fn private_key(der: &[u8]) -> Arc<dyn Params> {
    let info = PrivateKeyInfo::decode(der, &DecodingOptions::default())
        .unwrap()
        .1;
    let pkcs = DefaultPkcsOperatorBuilder::default().build();
    Arc::from(pkcs.private_key_info().decode(&info).unwrap())
}

fn rsa_recipient() -> X509Certificate {
    X509Certificate::decode(include_bytes!("data/env_recipient.der")).unwrap()
}

fn ec_recipient() -> X509Certificate {
    X509Certificate::decode(include_bytes!("data/env_ec_recipient.der")).unwrap()
}

#[test]
fn what_openssl_encrypted_with_aes_gcm_decrypts() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let rsa = private_key(include_bytes!("data/env_recipient_key.der"));
    let ec = KeyAgreeKey::new(
        private_key(include_bytes!("data/env_ec_recipient_key.der")),
        ec_recipient(),
    );
    let files: [(&str, &[u8], &dyn Params); 2] = [
        (
            "AES-256-GCM to RSA",
            include_bytes!("data/auth_gcm256_rsa.der"),
            rsa.as_ref(),
        ),
        (
            "AES-128-GCM to ECDH",
            include_bytes!("data/auth_gcm128_ecdh.der"),
            &ec,
        ),
    ];
    for (name, file, key) in files {
        let data = CmsAuthEnvelopedData::decode(file).unwrap();
        let recipient = &data.recipient_infos()[0];
        let content = oper
            .auth_enveloped_data()
            .decrypt(&data, recipient, key)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(content.as_slice(), CONTENT, "{name}");
    }
}

#[test]
fn what_is_encrypted_here_decrypts_for_each_recipient_with_gcm_and_ccm() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let kek: Vec<u8> = (0..16).collect();
    for cipher in [AES128_GCM, AES256_GCM, AES192_CCM] {
        let mut generator = CmsAuthEnvelopedDataGenerator::new();
        generator.add_recipient(KeyTransRecipientInfoGenerator::new(&rsa_recipient()));
        generator.add_recipient(KekRecipientInfoGenerator::new(b"kek", &kek));
        generator.add_recipient(PasswordRecipientInfoGenerator::new(
            "correct horse",
            "2.16.840.1.101.3.4.1.2".parse().unwrap(),
            vec![7; 16],
            1000,
        ));
        let data = oper
            .auth_enveloped_data()
            .generate(&generator, CONTENT, &cipher.parse().unwrap())
            .unwrap();
        let data = CmsAuthEnvelopedData::decode(&data.encode().unwrap()).unwrap();
        assert!(data.auth_attributes().is_none());

        let keys: [Arc<dyn Params>; 3] = [
            private_key(include_bytes!("data/env_recipient_key.der")),
            Arc::new(KeyOwned::new(kek.clone())),
            Arc::new(PasswordKey::new("correct horse")),
        ];
        for (recipient, key) in data.recipient_infos().iter().zip(keys) {
            let content = oper
                .auth_enveloped_data()
                .decrypt(&data, recipient, key.as_ref())
                .unwrap();
            assert_eq!(content.as_slice(), CONTENT, "{cipher}");
        }
    }
}

#[test]
fn the_authenticated_attributes_are_checked_with_the_content() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let kek: Vec<u8> = (0..32).collect();
    let mut generator = CmsAuthEnvelopedDataGenerator::new();
    generator.add_recipient(KekRecipientInfoGenerator::new(b"kek", &kek));
    // 一個自訂屬性，與內容一起受 AAD 保護
    generator.add_auth_attribute(
        Attribute::new(
            "1.2.3.4".parse::<tc_asn1::Asn1Oid>().unwrap(),
            vec![AttributeValue::Other(Asn1Object::OctetString(
                Asn1OctetString::new(b"label"),
            ))],
        )
        .unwrap(),
    );
    let data = oper
        .auth_enveloped_data()
        .generate(&generator, CONTENT, &AES256_GCM.parse().unwrap())
        .unwrap();
    // contentType 隨 authenticated attributes 加上
    assert_eq!(data.auth_attributes().unwrap().len(), 2);
    let key = KeyOwned::new(kek);
    let recipient = &data.recipient_infos()[0];
    let content = oper
        .auth_enveloped_data()
        .decrypt(&data, recipient, &key)
        .unwrap();
    assert_eq!(content.as_slice(), CONTENT);

    // 拿掉屬性，AAD 就不同，標籤驗不過
    let auth = data.auth_enveloped_data();
    let stripped = tc_asn1_cms::content::AuthEnvelopedData::new(
        auth.recipient_infos().to_vec(),
        auth.auth_encrypted_content_info().clone(),
        auth.mac().clone(),
    );
    let stripped = CmsAuthEnvelopedData::new(stripped);
    let result = oper
        .auth_enveloped_data()
        .decrypt(&stripped, recipient, &key);
    assert!(result.is_err());
}
