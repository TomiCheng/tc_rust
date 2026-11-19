use tc_cms::compressed::{CmsCompressedData, CmsCompressedDataGenerator};
use tc_cms::digested::CmsDigestedData;
use tc_cms::{CmsError, CmsOperatorBuilder, DefaultCmsOperatorBuilder};

const CONTENT: &[u8] = include_bytes!("data/cms_content.txt");

#[test]
fn what_openssl_compressed_decompresses() {
    let data = CmsCompressedData::decode(include_bytes!("data/compressed_openssl.der")).unwrap();
    assert_eq!(data.content().unwrap(), CONTENT);
}

#[test]
fn what_is_compressed_here_reads_back_and_a_limit_stops_a_larger_content() {
    let content = vec![b'a'; 100_000];
    let data = CmsCompressedDataGenerator::new()
        .generate(&content)
        .unwrap();
    let der = data.encode().unwrap();
    // 重複的內容壓得很小
    assert!(der.len() < 1000);

    let data = CmsCompressedData::decode(&der).unwrap();
    assert_eq!(data.content().unwrap(), content);
    assert_eq!(data.content_with_limit(100_000).unwrap(), content);
    let error = data.content_with_limit(99_999).unwrap_err();
    assert!(matches!(error, CmsError::ContentTooLarge));
}

#[test]
fn what_openssl_and_rfc_4134_digested_verifies() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let data = CmsDigestedData::decode(include_bytes!("data/digested_sha256.der")).unwrap();
    assert_eq!(oper.digested_data().verify(&data).unwrap(), CONTENT);

    // RFC 4134 6.0: SHA-1 over the sample content
    let data = CmsDigestedData::decode(include_bytes!("data/rfc4134_6.0.bin")).unwrap();
    let content = oper.digested_data().verify(&data).unwrap();
    assert!(content.starts_with(b"This is some sample content."));
}

#[test]
fn what_is_digested_here_verifies() {
    let oper = DefaultCmsOperatorBuilder::default().build();
    let data = oper
        .digested_data()
        .generate(CONTENT, &"2.16.840.1.101.3.4.2.1".parse().unwrap())
        .unwrap();
    let data = CmsDigestedData::decode(&data.encode().unwrap()).unwrap();
    assert_eq!(oper.digested_data().verify(&data).unwrap(), CONTENT);
}
