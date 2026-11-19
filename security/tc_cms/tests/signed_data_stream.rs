use std::io::Write;
use std::sync::Arc;

use tc_algo::Params;
use tc_cms::signed::{CmsSignedData, CmsSignedDataGenerator, SignerInfoGenerator};
use tc_cms::{CmsError, CmsOperator, CmsOperatorBuilder, DefaultCmsOperatorBuilder};
use tc_x509::cert::{X509Certificate, X509V3CertificateGenerator};
use tc_x509::operator::params::generate::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder};

const CONTENT: &[u8] = include_bytes!("data/cms_content.txt");

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

fn generator(
    x509: &dyn X509Operator,
    private: &Arc<dyn Params>,
    certificate: &X509Certificate,
    attributes: bool,
) -> CmsSignedDataGenerator {
    let factory = x509
        .signature_factory("SHA-256withRSA", private.clone())
        .unwrap();
    let mut signer = SignerInfoGenerator::new(factory, certificate).unwrap();
    if !attributes {
        signer = signer.without_signed_attributes();
    }
    let mut generator = CmsSignedDataGenerator::new();
    generator.add_signer(signer);
    generator.add_certificate(certificate.clone());
    generator
}

// 以串流寫出，內容分好幾次寫
fn stream(
    oper: &dyn CmsOperator,
    generator: &CmsSignedDataGenerator,
    content: &[u8],
    encapsulate: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = oper
        .signed_data()
        .open(generator, Box::new(&mut out), encapsulate)
        .unwrap();
    for chunk in content.chunks(1000) {
        writer.write_all(chunk).unwrap();
    }
    writer.finish().unwrap();
    out
}

fn verify_all(oper: &dyn CmsOperator, signed: &CmsSignedData, certificate: &X509Certificate) {
    for signer in signed.signer_infos() {
        oper.signed_data()
            .verify(signed, &signer, certificate)
            .unwrap();
    }
}

#[test]
fn a_streamed_signature_parses_back_as_a_stream_and_whole() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (private, certificate) = signer(x509.as_ref());
    // more than one segment of 4096 bytes
    let content: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
    let generator = generator(x509.as_ref(), &private, &certificate, true);
    let der = stream(oper.as_ref(), &generator, &content, true);

    let mut read = Vec::new();
    let parsed = oper
        .signed_data()
        .parse(&mut der.as_slice(), &mut read)
        .unwrap();
    assert_eq!(read, content);
    assert!(parsed.signed_content().is_none());
    assert_eq!(parsed.certificates(), std::slice::from_ref(&certificate));
    verify_all(oper.as_ref(), &parsed, &certificate);

    let whole = CmsSignedData::decode(&der).unwrap();
    assert_eq!(whole.signed_content(), Some(content.as_slice()));
    verify_all(oper.as_ref(), &whole, &certificate);
}

#[test]
fn a_detached_streamed_signature_verifies_with_the_content_read_apart() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (private, certificate) = signer(x509.as_ref());
    let generator = generator(x509.as_ref(), &private, &certificate, true);
    let der = stream(oper.as_ref(), &generator, CONTENT, false);

    let parsed = oper
        .signed_data()
        .parse_detached(&mut der.as_slice(), &mut &CONTENT[..])
        .unwrap();
    verify_all(oper.as_ref(), &parsed, &certificate);

    let changed = oper
        .signed_data()
        .parse_detached(&mut der.as_slice(), &mut &b"hello CMS"[..])
        .unwrap();
    let signer = &changed.signer_infos()[0];
    let result = oper.signed_data().verify(&changed, signer, &certificate);
    assert!(matches!(result, Err(CmsError::MessageDigestMismatch)));
}

#[test]
fn a_direct_signature_streams_out_but_needs_the_whole_content_to_verify() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let x509 = DefaultX509OperatorBuilder::default().build();
    let (private, certificate) = signer(x509.as_ref());
    let generator = generator(x509.as_ref(), &private, &certificate, false);
    let der = stream(oper.as_ref(), &generator, CONTENT, true);

    let whole = CmsSignedData::decode(&der).unwrap();
    verify_all(oper.as_ref(), &whole, &certificate);

    let parsed = oper
        .signed_data()
        .parse(&mut der.as_slice(), &mut std::io::sink())
        .unwrap();
    let signer = &parsed.signer_infos()[0];
    let result = oper.signed_data().verify(&parsed, signer, &certificate);
    assert!(matches!(result, Err(CmsError::MissingContent)));
}

#[test]
fn what_openssl_and_rfc_4134_signed_parses_as_a_stream() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let openssl: &[u8] = include_bytes!("data/cms_attached.der");
    let certificate = X509Certificate::decode(include_bytes!("data/cms_signer.der")).unwrap();
    let mut read = Vec::new();
    let parsed = oper
        .signed_data()
        .parse(&mut &openssl[..], &mut read)
        .unwrap();
    assert_eq!(read, CONTENT);
    verify_all(oper.as_ref(), &parsed, &certificate);

    // BER with indefinite lengths and the content in segments. Its signer signs the content
    // directly, with no signed attributes, so the digest alone cannot verify it
    let rfc: &[u8] = include_bytes!("data/rfc4134/4.5.bin");
    let mut read = Vec::new();
    let parsed = oper.signed_data().parse(&mut &rfc[..], &mut read).unwrap();
    assert_eq!(read, include_bytes!("data/rfc4134/ExContent.bin"));
    let certificates = parsed.certificates();
    let signer = &parsed.signer_infos()[0];
    let certificate = certificates
        .iter()
        .find(|certificate| signer.is_signer(certificate))
        .unwrap();
    let result = oper.signed_data().verify(&parsed, signer, certificate);
    assert!(matches!(result, Err(CmsError::MissingContent)));
}
