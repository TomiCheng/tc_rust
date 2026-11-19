use std::io::Write;
use std::sync::Arc;

use tc_algo::Params;
use tc_algo::params::key::KeyOwned;
use tc_asn1::{Decode, DecodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_cms::enveloped::{
    CmsEnvelopedData, CmsEnvelopedDataGenerator, KekRecipientInfoGenerator,
    KeyTransRecipientInfoGenerator,
};
use tc_cms::{CmsError, CmsOperator, CmsOperatorBuilder, DefaultCmsOperatorBuilder};
use tc_pkcs::{DefaultPkcsOperatorBuilder, PkcsOperatorBuilder};
use tc_x509::cert::X509Certificate;

const CONTENT: &[u8] = include_bytes!("data/cms_content.txt");
const AES256: &str = "2.16.840.1.101.3.4.1.42";

fn private_key(der: &[u8]) -> Arc<dyn Params> {
    let info = PrivateKeyInfo::decode(der, &DecodingOptions::default())
        .unwrap()
        .1;
    let pkcs = DefaultPkcsOperatorBuilder::default().build();
    Arc::from(pkcs.private_key_info().decode(&info).unwrap())
}

fn recipient() -> X509Certificate {
    X509Certificate::decode(include_bytes!("data/env_recipient.der")).unwrap()
}

// 以串流加密，內容分好幾次寫
fn stream(
    oper: &dyn CmsOperator,
    generator: &CmsEnvelopedDataGenerator,
    content: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = oper
        .enveloped_data()
        .open(generator, Box::new(&mut out), &AES256.parse().unwrap())
        .unwrap();
    for chunk in content.chunks(1000) {
        writer.write_all(chunk).unwrap();
    }
    writer.finish().unwrap();
    out
}

#[test]
fn a_streamed_message_decrypts_as_a_stream_and_whole_for_each_recipient() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let content: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
    let mut generator = CmsEnvelopedDataGenerator::new();
    generator.add_recipient(KeyTransRecipientInfoGenerator::new(&recipient()));
    generator.add_recipient(KekRecipientInfoGenerator::new(b"kek", &[9; 32]));
    let der = stream(oper.as_ref(), &generator, &content);

    let rsa = private_key(include_bytes!("data/env_recipient_key.der"));
    let mut read = Vec::new();
    oper.enveloped_data()
        .decrypt_stream(
            &mut der.as_slice(),
            &|info| info.is_recipient(&recipient()),
            rsa.as_ref(),
            &mut read,
        )
        .unwrap();
    assert_eq!(read, content);

    let mut read = Vec::new();
    oper.enveloped_data()
        .decrypt_stream(
            &mut der.as_slice(),
            &|recipient| recipient.kek_identifier() == Some(b"kek"),
            &KeyOwned::new(vec![9; 32]),
            &mut read,
        )
        .unwrap();
    assert_eq!(read, content);

    let whole = CmsEnvelopedData::decode(&der).unwrap();
    let recipient = &whole.recipient_infos()[0];
    let decrypted = oper
        .enveloped_data()
        .decrypt(&whole, recipient, rsa.as_ref())
        .unwrap();
    assert_eq!(decrypted.as_slice(), content.as_slice());
}

#[test]
fn what_openssl_and_rfc_4134_encrypted_decrypts_as_a_stream() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let rsa = private_key(include_bytes!("data/env_recipient_key.der"));
    let openssl: &[u8] = include_bytes!("data/env_aes256_pkcs1.der");
    let mut read = Vec::new();
    oper.enveloped_data()
        .decrypt_stream(&mut &openssl[..], &|_| true, rsa.as_ref(), &mut read)
        .unwrap();
    assert_eq!(read, CONTENT);

    let bob = private_key(include_bytes!("data/rfc4134/BobPrivRSAEncrypt.pri"));
    let ex_content: &[u8] = include_bytes!("data/rfc4134/ExContent.bin");
    for file in [
        &include_bytes!("data/rfc4134/5.1.bin")[..],
        &include_bytes!("data/rfc4134/5.2.bin")[..],
    ] {
        let mut read = Vec::new();
        oper.enveloped_data()
            .decrypt_stream(
                &mut &file[..],
                &|recipient| recipient.kek_identifier().is_none(),
                bob.as_ref(),
                &mut read,
            )
            .unwrap();
        assert_eq!(read, ex_content);
    }
}

#[test]
fn no_matching_recipient_is_refused() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let mut generator = CmsEnvelopedDataGenerator::new();
    generator.add_recipient(KekRecipientInfoGenerator::new(b"kek", &[9; 32]));
    let der = stream(oper.as_ref(), &generator, CONTENT);
    let result = oper.enveloped_data().decrypt_stream(
        &mut der.as_slice(),
        &|recipient| recipient.is_password(),
        &KeyOwned::new(vec![9; 32]),
        &mut std::io::sink(),
    );
    assert!(matches!(result, Err(CmsError::WrongRecipientKey)));
}
