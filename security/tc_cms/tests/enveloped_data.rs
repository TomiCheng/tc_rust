use std::sync::Arc;

use tc_algo::Params;
use tc_asn1::{Decode, DecodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_cms::enveloped::{
    CmsEnvelopedData, CmsEnvelopedDataGenerator, KeyTransRecipientInfoGenerator,
};
use tc_cms::{CmsOperatorBuilder, DefaultCmsOperatorBuilder};
use tc_pkcs::{DefaultPkcsOperatorBuilder, PkcsOperatorBuilder};
use tc_x509::cert::X509Certificate;

const CONTENT: &[u8] = include_bytes!("data/cms_content.txt");
const AES128: &str = "2.16.840.1.101.3.4.1.2";
const AES256: &str = "2.16.840.1.101.3.4.1.42";
const DES_EDE3: &str = "1.2.840.113549.3.7";

fn recipient() -> X509Certificate {
    X509Certificate::decode(include_bytes!("data/env_recipient.der")).unwrap()
}

// OpenSSL 寫的 PKCS#8，以 tc_pkcs 讀成 RsaKey
fn recipient_key() -> Arc<dyn Params> {
    let der = include_bytes!("data/env_recipient_key.der");
    let info = PrivateKeyInfo::decode(der, &DecodingOptions::default())
        .unwrap()
        .1;
    let pkcs = DefaultPkcsOperatorBuilder::default().build();
    Arc::from(pkcs.private_key_info().decode(&info).unwrap())
}

#[test]
fn what_openssl_encrypted_with_pkcs1_and_oaep_decrypts() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let key = recipient_key();
    let files: [(&str, &[u8]); 3] = [
        (
            "AES-256 PKCS#1",
            include_bytes!("data/env_aes256_pkcs1.der"),
        ),
        (
            "AES-128 OAEP SHA-256",
            include_bytes!("data/env_aes128_oaep256.der"),
        ),
        ("DES-EDE3 PKCS#1", include_bytes!("data/env_des3_pkcs1.der")),
    ];
    for (name, file) in files {
        let enveloped = CmsEnvelopedData::decode(file).unwrap();
        let recipients = enveloped.recipient_infos();
        assert_eq!(recipients.len(), 1, "{name}");
        assert!(recipients[0].is_recipient(&recipient()), "{name}");
        let content = oper
            .enveloped_data()
            .decrypt(&enveloped, &recipients[0], key.as_ref())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(content.as_slice(), CONTENT, "{name}");
    }
}

#[test]
fn what_is_encrypted_here_decrypts_with_each_cipher_and_padding() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let key = recipient_key();
    for (cipher, oaep) in [
        (AES128, None),
        (AES256, Some("2.16.840.1.101.3.4.2.1")),
        (DES_EDE3, Some("1.3.14.3.2.26")),
    ] {
        let mut recipient_info = KeyTransRecipientInfoGenerator::new(&recipient());
        if let Some(digest) = oaep {
            recipient_info = recipient_info.with_oaep(digest.parse().unwrap());
        }
        let mut generator = CmsEnvelopedDataGenerator::new();
        generator.add_recipient(recipient_info);
        let enveloped = oper
            .enveloped_data()
            .generate(&generator, CONTENT, &cipher.parse().unwrap())
            .unwrap();

        let enveloped = CmsEnvelopedData::decode(&enveloped.encode().unwrap()).unwrap();
        assert_eq!(
            enveloped
                .content_encryption_algorithm()
                .algorithm()
                .to_string(),
            cipher
        );
        let recipient = &enveloped.recipient_infos()[0];
        let content = oper
            .enveloped_data()
            .decrypt(&enveloped, recipient, key.as_ref())
            .unwrap();
        assert_eq!(content.as_slice(), CONTENT, "{cipher}");
    }
}

#[test]
fn an_unknown_content_cipher_is_refused() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let mut generator = CmsEnvelopedDataGenerator::new();
    generator.add_recipient(KeyTransRecipientInfoGenerator::new(&recipient()));
    let error = oper
        .enveloped_data()
        .generate(&generator, CONTENT, &"1.2.3.4".parse().unwrap())
        .unwrap_err();
    assert!(matches!(error, tc_cms::CmsError::UnknownAlgorithm));
}
