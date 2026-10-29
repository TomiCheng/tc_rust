use tc_pem::{PemHeader, PemObject};

#[test]
fn a_header_keeps_its_name_and_value_and_prints_them_joined_by_a_colon() {
    let header = PemHeader::new("Proc-Type", "4,ENCRYPTED");
    assert_eq!(header.name(), "Proc-Type");
    assert_eq!(header.value(), "4,ENCRYPTED");
    assert_eq!(header.to_string(), "Proc-Type:4,ENCRYPTED");
}

#[test]
fn headers_are_equal_only_when_name_and_value_both_match() {
    let header = PemHeader::new("Proc-Type", "4,ENCRYPTED");
    assert_eq!(header, PemHeader::new("Proc-Type", "4,ENCRYPTED"));
    assert_ne!(header, PemHeader::new("Proc-Type", "4,MIC-ONLY"));
    assert_ne!(header, PemHeader::new("DEK-Info", "4,ENCRYPTED"));
}

#[test]
fn an_object_keeps_its_type_headers_and_content() {
    let plain = PemObject::new("CERTIFICATE", vec![1, 2, 3]);
    assert_eq!(plain.pem_type(), "CERTIFICATE");
    assert!(plain.headers().is_empty());
    assert_eq!(plain.content(), [1, 2, 3]);

    let headers = vec![
        PemHeader::new("Proc-Type", "4,ENCRYPTED"),
        PemHeader::new("DEK-Info", "DES-CBC,0001020304050607"),
    ];
    let encrypted = PemObject::new("RSA PRIVATE KEY", vec![4; 8]).with_headers(headers.clone());
    assert_eq!(encrypted.headers(), headers);
    assert_eq!(encrypted.content(), [4; 8]);
}

#[test]
fn debug_output_shows_the_content_length_but_not_the_content() {
    let object = PemObject::new("PRIVATE KEY", vec![0xab; 3]);
    let debug = format!("{object:?}");
    assert_eq!(
        debug,
        r#"PemObject { pem_type: "PRIVATE KEY", headers: [], content_len: 3 }"#
    );
}
