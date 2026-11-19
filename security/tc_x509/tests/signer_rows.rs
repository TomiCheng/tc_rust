use std::sync::Arc;

use tc_algo::Params;
use tc_x509::cert::{X509Certificate, X509V3CertificateGenerator};
use tc_x509::operator::params::generate::{EcKeyGenParams, RsaKeyGenParams};
use tc_x509::{DefaultX509OperatorBuilder, X509Operator, X509OperatorBuilder};

// The certificate verifies with its own key, by the signature algorithm it carries
fn self_signed_verifies(oper: &dyn X509Operator, certificate: &X509Certificate) -> bool {
    let key = oper
        .spki()
        .decode(certificate.subject_public_key_info())
        .unwrap();
    let provider = oper.verifier_factory_provider(Arc::from(key));
    certificate.is_signature_valid(provider.as_ref()).unwrap()
}

fn pair(
    oper: &dyn X509Operator,
    name: &str,
    params: Option<&dyn Params>,
) -> (Box<dyn Params>, Arc<dyn Params>) {
    let mut key_gen = oper.key_pair_generator().get_by_name(name).unwrap();
    if let Some(params) = params {
        key_gen.init(params).unwrap();
    }
    let (public, private) = key_gen.generate().unwrap().into_parts();
    (public, Arc::from(private))
}

#[test]
fn the_certificates_openssl_signed_with_each_algorithm_verify() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let files: [(&str, &[u8]); 6] = [
        (
            "ECDSA P-256 SHA-256",
            include_bytes!("data/signer_ecdsa_p256_sha256.der"),
        ),
        (
            "ECDSA P-384 SHA-384",
            include_bytes!("data/signer_ecdsa_p384_sha384.der"),
        ),
        ("Ed25519", include_bytes!("data/signer_ed25519.der")),
        ("Ed448", include_bytes!("data/signer_ed448.der")),
        ("RSA SHA-384", include_bytes!("data/signer_rsa_sha384.der")),
        (
            "RSASSA-PSS SHA-256",
            include_bytes!("data/signer_rsa_pss_sha256.der"),
        ),
    ];
    for (name, file) in files {
        let certificate = X509Certificate::decode(file).unwrap();
        assert!(self_signed_verifies(oper.as_ref(), &certificate), "{name}");
    }
}

#[test]
fn a_certificate_signed_by_each_row_verifies() {
    let oper = DefaultX509OperatorBuilder::default().build();
    let rsa = RsaKeyGenParams::new(2048);
    let p256 = EcKeyGenParams::new("P-256");
    let keys = [
        ("RSA", Some(&rsa as &dyn Params)),
        ("EC", Some(&p256 as &dyn Params)),
        ("Ed25519", None),
        ("Ed448", None),
    ]
    .map(|(name, params)| (name, pair(oper.as_ref(), name, params)));
    let rows: [(&str, &str); 17] = [
        ("RSA", "SHA-1withRSA"),
        ("RSA", "SHA224withRSA"),
        ("RSA", "SHA-256withRSA"),
        ("RSA", "SHA384withRSAEncryption"),
        ("RSA", "SHA-512withRSA"),
        ("RSA", "SHA-1withRSAandMGF1"),
        ("RSA", "SHA-224withRSAandMGF1"),
        ("RSA", "SHA256withRSAandMGF1"),
        ("RSA", "SHA-384withRSAandMGF1"),
        ("RSA", "SHA-512withRSAandMGF1"),
        ("EC", "SHA-1withECDSA"),
        ("EC", "SHA-224withECDSA"),
        ("EC", "SHA256withECDSA"),
        ("EC", "SHA-384withECDSA"),
        ("EC", "ECDSAwithSHA512"),
        ("Ed25519", "Ed25519"),
        ("Ed448", "Ed448"),
    ];
    for (key, row) in rows {
        let (_, (public, private)) = keys.iter().find(|(name, _)| *name == key).unwrap();
        let mut generator = X509V3CertificateGenerator::new();
        generator.set_issuer_by_str("CN=row").unwrap();
        generator.set_subject_by_str("CN=row").unwrap();
        generator.set_validity_days(1).unwrap();
        generator.set_subject_public_key_info(oper.spki().encode(public.as_ref()).unwrap());
        let factory = oper.signature_factory(row, private.clone()).unwrap();
        let certificate = generator.generate(factory.as_ref()).unwrap();

        let certificate = X509Certificate::decode(&certificate.encode().unwrap()).unwrap();
        assert!(self_signed_verifies(oper.as_ref(), &certificate), "{row}");
    }
}
