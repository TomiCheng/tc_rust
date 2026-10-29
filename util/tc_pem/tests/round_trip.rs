use std::error::Error;
use std::io::{self, ErrorKind};

use tc_pem::{
    PemGenerationError, PemHeader, PemObject, PemObjectGenerator, PemObjectParser, PemReader,
    PemWriter,
};

fn write(object: &impl PemObjectGenerator) -> io::Result<Vec<u8>> {
    let mut writer = PemWriter::new(Vec::new());
    writer.write_object(object)?;
    Ok(writer.into_inner())
}

fn read_all(pem: &[u8]) -> io::Result<Vec<PemObject>> {
    let mut reader = PemReader::new(pem);
    let mut objects = Vec::new();
    while let Some(object) = reader.read_pem_object()? {
        objects.push(object);
    }
    Ok(objects)
}

#[test]
fn written_pem_matches_what_python_ssl_writes_for_a_certificate() {
    // ssl.DER_cert_to_PEM_cert(bytes(range(n)))
    let full_line = "-----BEGIN CERTIFICATE-----\n\
        AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n\
        -----END CERTIFICATE-----\n";
    let three_lines = "-----BEGIN CERTIFICATE-----\n\
        AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n\
        MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n\
        YGFiYw==\n\
        -----END CERTIFICATE-----\n";
    for (len, expected) in [(48, full_line), (100, three_lines)] {
        let object = PemObject::new("CERTIFICATE", (0..len).collect());
        assert_eq!(
            String::from_utf8(write(&object).unwrap()).unwrap(),
            expected
        );
        let read = read_all(expected.as_bytes()).unwrap();
        assert_eq!(read[0].content(), object.content());
    }
}

#[test]
fn headers_and_content_survive_a_round_trip_with_crlf_line_endings() {
    let headers = vec![
        PemHeader::new("Proc-Type", "4,ENCRYPTED"),
        PemHeader::new("DEK-Info", "DES-EDE3-CBC,0001020304050607"),
    ];
    let object = PemObject::new("RSA PRIVATE KEY", (0..=255).collect()).with_headers(headers);
    let pem = write(&object).unwrap();
    let crlf = String::from_utf8(pem).unwrap().replace('\n', "\r\n");

    let read = read_all(crlf.as_bytes()).unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].pem_type(), "RSA PRIVATE KEY");
    assert_eq!(read[0].headers(), object.headers());
    assert_eq!(read[0].content(), object.content());
}

#[test]
fn several_objects_are_read_in_order_skipping_text_around_them() {
    let mut pem = b"Bag Attributes\n    friendlyName: test\n".to_vec();
    pem.extend(write(&PemObject::new("CERTIFICATE", vec![1, 2, 3])).unwrap());
    pem.extend(b"\nsome text in between\n");
    pem.extend(write(&PemObject::new("PRIVATE KEY", Vec::new())).unwrap());

    let read = read_all(&pem).unwrap();
    assert_eq!(read.len(), 2);
    assert_eq!(
        (read[0].pem_type(), read[0].content()),
        ("CERTIFICATE", &[1, 2, 3][..])
    );
    assert_eq!(
        (read[1].pem_type(), read[1].content()),
        ("PRIVATE KEY", &[][..])
    );
}

#[test]
fn an_end_line_for_another_type_is_rejected() {
    let pem = b"-----BEGIN CERTIFICATE-----\nAAEC\n-----END PRIVATE KEY-----\n";
    let error = read_all(pem).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "END CERTIFICATE was not found.");
}

#[test]
fn a_header_with_a_line_break_is_rejected_before_anything_is_written() {
    let object = PemObject::new("CERTIFICATE", vec![1])
        .with_headers(vec![PemHeader::new("Comment", "two\nlines")]);
    let mut writer = PemWriter::new(Vec::new());
    let error = writer.write_object(&object).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(writer.into_inner().is_empty());
}

struct Failing;

impl PemObjectGenerator for Failing {
    fn generate(&self) -> Result<PemObject, PemGenerationError> {
        Err(PemGenerationError::with_source(
            "cannot encode key",
            io::Error::other("unsupported"),
        ))
    }
}

#[test]
fn a_generator_failure_reaches_the_caller_with_its_cause() {
    let error = write(&Failing).unwrap_err();
    let generation = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<PemGenerationError>())
        .unwrap();
    assert_eq!(generation.message(), "cannot encode key");
    assert_eq!(generation.source().unwrap().to_string(), "unsupported");
}

struct ContentLength;

impl PemObjectParser for ContentLength {
    type Output = usize;

    fn parse_object(&self, obj: &PemObject) -> io::Result<usize> {
        Ok(obj.content().len())
    }
}

#[test]
fn a_parser_turns_a_read_object_into_its_own_type() {
    let pem = write(&PemObject::new("CERTIFICATE", vec![0; 7])).unwrap();
    let object = PemReader::new(&pem[..]).read_pem_object().unwrap().unwrap();
    assert_eq!(ContentLength.parse_object(&object).unwrap(), 7);
}
