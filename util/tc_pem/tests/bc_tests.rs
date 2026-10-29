//! 移植自 bc-csharp 的 `Utilities.IO.Pem.Tests.AllTests`。

use tc_pem::{PemHeader, PemObject, PemReader, PemWriter};

fn length_test(pem_type: &str, headers: Vec<PemHeader>, len: usize) {
    let object = PemObject::new(pem_type, vec![0; len]).with_headers(headers);
    let mut writer = PemWriter::new(Vec::new());
    writer.write_object(&object).unwrap();
    let size = writer.get_output_size(&object);
    assert_eq!(writer.into_inner().len(), size, "{pem_type} {len}");
}

#[test]
fn the_predicted_output_size_matches_what_is_written() {
    for len in (1..60).chain(100..104).chain(1000..1004) {
        length_test("CERTIFICATE", Vec::new(), len);
    }
    length_test(
        "RSA PRIVATE KEY",
        vec![
            PemHeader::new("Proc-Type", "4,ENCRYPTED"),
            PemHeader::new("DEK-Info", "DES3,0001020304050607"),
        ],
        103,
    );
}

#[test]
fn a_begin_line_without_a_type_runs_out_of_data() {
    let error = PemReader::new(&b"-----BEGIN \n"[..])
        .read_pem_object()
        .unwrap_err();
    assert_eq!(error.to_string(), "ran out of data before consuming type");
}

#[test]
fn a_body_that_is_not_base64_is_malformed_pem_data() {
    let pem = b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n";
    let error = PemReader::new(&pem[..]).read_pem_object().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        error.to_string().starts_with("malformed PEM data:"),
        "{error}"
    );
}
