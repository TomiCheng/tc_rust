use std::sync::Arc;

use tc_asn1_x509::ext::{Extension, ExtensionId};
use tc_pkcs::PkcsError;
use tc_pkcs::csr::{Pkcs10CertificationRequest, Pkcs10CertificationRequestBuilder};
use tc_x509::operator::params::generate::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder};

// subjectAltName of dNSName example.com
const SAN: &[u8] = b"\x30\x0d\x82\x0bexample.com";

fn verify_own_key(
    x509: &dyn X509Operator,
    csr: &Pkcs10CertificationRequest,
) -> Result<(), PkcsError> {
    let public = csr.public_key(x509)?;
    csr.verify(x509.verifier_factory_provider(Arc::from(public)).as_ref())
}

#[test]
fn a_request_openssl_made_reads_and_verifies_with_its_own_key() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let csr = Pkcs10CertificationRequest::decode(include_bytes!("data/csr_rsa.der")).unwrap();

    // OpenSSL's /CN=example/O=Acme, written in the order of RFC 4514
    assert_eq!(csr.subject().to_string(), "O=Acme,CN=example");
    let extensions = csr.requested_extensions().unwrap().unwrap();
    let san = extensions.get(ExtensionId::SUBJECT_ALT_NAME).unwrap();
    assert_eq!(san.extn_value(), SAN);
    verify_own_key(x509.as_ref(), &csr).unwrap();
}

#[test]
fn a_generated_request_reads_back_with_its_extensions_and_verifies() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let mut key_gen = x509.key_pair_generator().get_by_name("RSA").unwrap();
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let (public, private) = key_gen.generate().unwrap().into_parts();

    let mut builder = Pkcs10CertificationRequestBuilder::new();
    builder.set_subject_by_str("CN=example,O=Acme").unwrap();
    builder.set_subject_public_key_info(x509.spki().encode(public.as_ref()).unwrap());
    builder.add_extension(Extension::new(ExtensionId::SUBJECT_ALT_NAME, false, SAN));
    let factory = x509
        .signature_factory("SHA-256withRSA", Arc::from(private))
        .unwrap();
    let csr = builder.generate(factory.as_ref()).unwrap();

    let csr = Pkcs10CertificationRequest::decode(&csr.encode().unwrap()).unwrap();
    assert_eq!(csr.subject().to_string(), "CN=example,O=Acme");
    let extensions = csr.requested_extensions().unwrap().unwrap();
    assert_eq!(extensions.extensions().len(), 1);
    verify_own_key(x509.as_ref(), &csr).unwrap();
}

#[test]
fn a_request_signed_by_another_key_does_not_verify() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let mut key_gen = x509.key_pair_generator().get_by_name("RSA").unwrap();
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let (public, _) = key_gen.generate().unwrap().into_parts();
    let (_, other) = key_gen.generate().unwrap().into_parts();

    let mut builder = Pkcs10CertificationRequestBuilder::new();
    builder.set_subject_by_str("CN=example").unwrap();
    builder.set_subject_public_key_info(x509.spki().encode(public.as_ref()).unwrap());
    let factory = x509
        .signature_factory("SHA-256withRSA", Arc::from(other))
        .unwrap();
    let csr = builder.generate(factory.as_ref()).unwrap();

    let error = verify_own_key(x509.as_ref(), &csr).unwrap_err();
    assert!(matches!(error, PkcsError::InvalidSignature));
}

#[test]
fn a_request_needs_a_subject_and_a_public_key() {
    let x509 = DefaultX509OperatorBuilder::default().build();
    let mut key_gen = x509.key_pair_generator().get_by_name("RSA").unwrap();
    key_gen.init(&RsaKeyGenParams::new(1024)).unwrap();
    let (_, private) = key_gen.generate().unwrap().into_parts();
    let factory = x509
        .signature_factory("SHA-256withRSA", Arc::from(private))
        .unwrap();

    let mut builder = Pkcs10CertificationRequestBuilder::new();
    let error = builder.generate(factory.as_ref()).unwrap_err();
    assert!(matches!(error, PkcsError::MissingField("subject")));
    builder.set_subject_by_str("CN=example").unwrap();
    let error = builder.generate(factory.as_ref()).unwrap_err();
    assert!(matches!(
        error,
        PkcsError::MissingField("subject_public_key_info")
    ));
}
