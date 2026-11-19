use std::sync::Arc;

use tc_algo::Params;
use tc_cms::signed::{CmsSignedData, CmsSignedDataGenerator, SignerInfoGenerator};
use tc_cms::{CmsError, CmsOperator, CmsOperatorBuilder, DefaultCmsOperatorBuilder};
use tc_x509::cert::{X509Certificate, X509V3CertificateGenerator};
use tc_x509::operator::params::generate::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder};

const CONTENT: &[u8] = include_bytes!("data/cms_content.txt");

fn openssl_signer() -> X509Certificate {
    X509Certificate::decode(include_bytes!("data/cms_signer.der")).unwrap()
}

// 一把 RSA 金鑰與它的自簽憑證
fn signer(x509: &dyn X509Operator) -> (Arc<dyn Params>, X509Certificate) {
    let mut key_gen = x509.key_pair_generator().get_by_name("RSA").unwrap();
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let (public, private) = key_gen.generate().unwrap().into_parts();
    let private: Arc<dyn Params> = Arc::from(private);
    let mut generator = X509V3CertificateGenerator::new();
    generator.set_issuer_by_str("CN=signer").unwrap();
    generator.set_subject_by_str("CN=signer").unwrap();
    generator.set_validity_days(365).unwrap();
    generator.set_subject_public_key_info(x509.spki().encode(public.as_ref()).unwrap());
    let factory = x509
        .signature_factory("SHA-256withRSA", private.clone())
        .unwrap();
    (private, generator.generate(factory.as_ref()).unwrap())
}

fn verify_all(
    oper: &dyn CmsOperator,
    signed: &CmsSignedData,
    certificate: &X509Certificate,
) -> Result<(), CmsError> {
    for signer in signed.signer_infos() {
        assert!(signer.is_signer(certificate));
        oper.signed_data().verify(signed, &signer, certificate)?;
    }
    Ok(())
}

#[test]
fn what_openssl_signed_verifies_with_attributes_without_them_and_detached() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let certificate = openssl_signer();

    let attached = CmsSignedData::decode(include_bytes!("data/cms_attached.der")).unwrap();
    assert_eq!(attached.signed_content(), Some(CONTENT));
    assert_eq!(attached.certificates(), std::slice::from_ref(&certificate));
    verify_all(oper.as_ref(), &attached, &certificate).unwrap();

    let no_attributes = CmsSignedData::decode(include_bytes!("data/cms_noattr.der")).unwrap();
    assert!(
        no_attributes.signer_infos()[0]
            .signed_attributes()
            .is_none()
    );
    verify_all(oper.as_ref(), &no_attributes, &certificate).unwrap();

    let der = include_bytes!("data/cms_detached.der");
    let detached = CmsSignedData::decode_detached(der, CONTENT.to_vec()).unwrap();
    assert!(detached.is_detached());
    verify_all(oper.as_ref(), &detached, &certificate).unwrap();

    let without_content = CmsSignedData::decode(der).unwrap();
    let error = verify_all(oper.as_ref(), &without_content, &certificate).unwrap_err();
    assert!(matches!(error, CmsError::MissingContent));
}

#[test]
fn a_signature_made_here_verifies_and_a_changed_content_does_not() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (private, certificate) = signer(x509.as_ref());

    for attributes in [true, false] {
        let factory = x509
            .signature_factory("SHA-256withRSA", private.clone())
            .unwrap();
        let mut signer = SignerInfoGenerator::new(factory, &certificate).unwrap();
        if !attributes {
            signer = signer.without_signed_attributes();
        }
        let mut generator = CmsSignedDataGenerator::new();
        generator.add_signer(signer);
        generator.add_certificate(certificate.clone());
        let signed = oper
            .signed_data()
            .generate(&generator, CONTENT, true)
            .unwrap();

        let signed = CmsSignedData::decode(&signed.encode().unwrap()).unwrap();
        assert_eq!(signed.signed_content(), Some(CONTENT));
        verify_all(oper.as_ref(), &signed, &certificate).unwrap();

        let changed = CmsSignedData::with_detached_content(
            signed.signed_data().clone(),
            b"hello CMS".to_vec(),
        );
        let error = verify_all(oper.as_ref(), &changed, &certificate).unwrap_err();
        let expected = if attributes {
            matches!(error, CmsError::MessageDigestMismatch)
        } else {
            matches!(error, CmsError::InvalidSignature)
        };
        assert!(expected, "{error}");
    }
}

#[test]
fn a_detached_signature_needs_the_content_and_another_key_does_not_verify() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (private, certificate) = signer(x509.as_ref());
    let (_, other) = signer(x509.as_ref());

    let factory = x509.signature_factory("SHA-256withRSA", private).unwrap();
    let mut generator = CmsSignedDataGenerator::new();
    generator.add_signer(SignerInfoGenerator::new(factory, &certificate).unwrap());
    let der = oper
        .signed_data()
        .generate(&generator, CONTENT, false)
        .unwrap()
        .encode()
        .unwrap();

    let signed = CmsSignedData::decode_detached(&der, CONTENT.to_vec()).unwrap();
    assert!(signed.certificates().is_empty());
    verify_all(oper.as_ref(), &signed, &certificate).unwrap();

    let signer = &signed.signer_infos()[0];
    let error = oper
        .signed_data()
        .verify(&signed, signer, &other)
        .unwrap_err();
    assert!(matches!(error, CmsError::InvalidSignature));
}
