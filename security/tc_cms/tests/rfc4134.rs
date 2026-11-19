// RFC 4134 的 CMS 範例，同 BC 的 Rfc4134Test
use std::sync::Arc;

use tc_algo::Params;
use tc_asn1::{Decode, DecodingOptions};
use tc_asn1_pkcs::PrivateKeyInfo;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_cms::enveloped::CmsEnvelopedData;
use tc_cms::signed::CmsSignedData;
use tc_cms::{CmsOperator, CmsOperatorBuilder, DefaultCmsOperatorBuilder};
use tc_pkcs::{DefaultPkcsOperatorBuilder, PkcsOperatorBuilder};
use tc_x509::cert::X509Certificate;
use tc_x509::{DefaultX509OperatorBuilder, X509OperatorBuilder};

const EX_CONTENT: &[u8] = include_bytes!("data/rfc4134/ExContent.bin");

// 每個簽署者以 SignedData 附帶的憑證驗證，同 BC 的 VerifySignatures。DSA 公鑰沒有參數時從
// Carl 的憑證繼承，同 BC 的 GetInheritedKey：由呼叫端組出公鑰，再以 verify_with_key 驗證
fn verify_signatures(oper: &dyn CmsOperator, signed: &CmsSignedData) {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let certificates = signed.certificates();
    let signers = signed.signer_infos();
    assert!(!signers.is_empty());
    for signer in signers {
        let certificate = certificates
            .iter()
            .find(|certificate| signer.is_signer(certificate))
            .expect("the signer's certificate is in the SignedData");
        let spki = certificate.subject_public_key_info();
        if spki.algorithm().parameters().is_some() {
            oper.signed_data()
                .verify(signed, &signer, certificate)
                .unwrap();
        } else {
            let carl =
                X509Certificate::decode(include_bytes!("data/rfc4134/CarlDSSSelf.cer")).unwrap();
            let inherited = SubjectPublicKeyInfo::new(
                carl.subject_public_key_info().algorithm().clone(),
                spki.subject_public_key().clone(),
            );
            let key = x509.spki().decode(&inherited).unwrap();
            oper.signed_data()
                .verify_with_key(signed, &signer, Arc::from(key))
                .unwrap();
        }
    }
}

fn bob_key() -> Arc<dyn Params> {
    let der = include_bytes!("data/rfc4134/BobPrivRSAEncrypt.pri");
    let info = PrivateKeyInfo::decode(der, &DecodingOptions::default())
        .unwrap()
        .1;
    let pkcs = DefaultPkcsOperatorBuilder::default().build();
    Arc::from(pkcs.private_key_info().decode(&info).unwrap())
}

#[test]
fn example_4_2_signed_with_rsa_verifies() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let signed = CmsSignedData::decode(include_bytes!("data/rfc4134/4.2.bin")).unwrap();
    assert_eq!(signed.signed_content(), Some(EX_CONTENT));
    verify_signatures(oper.as_ref(), &signed);
}

#[test]
fn example_4_5_signed_with_rsa_and_a_key_identifier_verifies() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let signed = CmsSignedData::decode(include_bytes!("data/rfc4134/4.5.bin")).unwrap();
    verify_signatures(oper.as_ref(), &signed);
}

#[test]
fn example_5_1_enveloped_with_des_ede3_for_bob_decrypts() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let enveloped = CmsEnvelopedData::decode(include_bytes!("data/rfc4134/5.1.bin")).unwrap();
    let recipient = &enveloped.recipient_infos()[0];
    let content = oper
        .enveloped_data()
        .decrypt(&enveloped, recipient, bob_key().as_ref())
        .unwrap();
    assert_eq!(content.as_slice(), EX_CONTENT);
}

#[test]
fn example_5_2_enveloped_with_rc2_for_bob_decrypts() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let enveloped = CmsEnvelopedData::decode(include_bytes!("data/rfc4134/5.2.bin")).unwrap();
    let recipient = &enveloped.recipient_infos()[0];
    let content = oper
        .enveloped_data()
        .decrypt(&enveloped, recipient, bob_key().as_ref())
        .unwrap();
    assert_eq!(content.as_slice(), EX_CONTENT);
}

#[test]
fn the_dsa_examples_verify() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let attached: [(&str, &[u8]); 4] = [
        ("4.1", include_bytes!("data/rfc4134/4.1.bin")),
        ("4.4", include_bytes!("data/rfc4134/4.4.bin")),
        ("4.6", include_bytes!("data/rfc4134/4.6.bin")),
        ("4.7", include_bytes!("data/rfc4134/4.7.bin")),
    ];
    for (name, file) in attached {
        let signed = CmsSignedData::decode(file).unwrap_or_else(|error| panic!("{name}: {error}"));
        verify_signatures(oper.as_ref(), &signed);
    }

    // 4.3 is detached: the content is ExContent
    let signed =
        CmsSignedData::decode_detached(include_bytes!("data/rfc4134/4.3.bin"), EX_CONTENT.to_vec())
            .unwrap();
    verify_signatures(oper.as_ref(), &signed);
}

#[test]
fn the_countersignature_of_example_4_4_verifies_with_alices_rsa_certificate() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let signed = CmsSignedData::decode(include_bytes!("data/rfc4134/4.4.bin")).unwrap();
    let signer = &signed.signer_infos()[0];
    let counters = signer.counter_signatures().unwrap();
    assert_eq!(counters.len(), 1);
    assert!(counters[0].is_counter_signature());

    let alice =
        X509Certificate::decode(include_bytes!("data/rfc4134/AliceRSASignByCarl.cer")).unwrap();
    assert!(counters[0].is_signer(&alice));
    oper.signed_data()
        .verify(&signed, &counters[0], &alice)
        .unwrap();
}
