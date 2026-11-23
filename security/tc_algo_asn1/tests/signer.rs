use tc_algo::params::generate::EcKeyGenParams;
use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};
use tc_algo_asn1::{AlgoAsn1, AlgoAsn1Builder, AlgoAsn1Error, DefaultAlgoAsn1Builder};
use tc_asn1::{Asn1Object, Decode, DecodingOptions};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::Certificate;

fn algo() -> Box<dyn Algo> {
    DefaultAlgoBuilder::default().build()
}

fn asn1() -> Box<dyn AlgoAsn1> {
    DefaultAlgoAsn1Builder::default().build()
}

const ROWS: [&str; 22] = [
    "SHA-1withRSA",
    "SHA-224withRSA",
    "SHA-256withRSA",
    "SHA-384withRSA",
    "SHA-512withRSA",
    "SHA-1withRSAandMGF1",
    "SHA-224withRSAandMGF1",
    "SHA-256withRSAandMGF1",
    "SHA-384withRSAandMGF1",
    "SHA-512withRSAandMGF1",
    "SHA-1withECDSA",
    "SHA-224withECDSA",
    "SHA-256withECDSA",
    "SHA-384withECDSA",
    "SHA-512withECDSA",
    "Ed25519",
    "Ed448",
    "SHA-1withDSA",
    "SHA-224withDSA",
    "SHA-256withDSA",
    "SM3withSM2",
    "SHA256withSM2",
];

#[test]
fn every_row_finds_its_signer_again_from_the_algorithm_identifier_it_writes() {
    let asn1 = asn1();
    for name in ROWS {
        let signer = asn1.signer().get_by_name(name).unwrap();
        let again = asn1.signer().get_by_id(signer.algorithm()).unwrap();
        assert_eq!(again.algorithm(), signer.algorithm(), "{name}");
    }
}

#[test]
fn aliases_name_the_same_algorithm_whatever_their_case() {
    let asn1 = asn1();
    let signer = asn1
        .signer()
        .get_by_name("sha256withrsaencryption")
        .unwrap();
    let algorithm = signer.algorithm();
    assert_eq!(algorithm.algorithm().to_string(), "1.2.840.113549.1.1.11");
    assert!(matches!(algorithm.parameters(), Some(Asn1Object::Null(_))));
    assert_eq!(
        asn1.signer()
            .get_by_name("ECDSAwithSHA512")
            .unwrap()
            .algorithm(),
        asn1.signer()
            .get_by_name("SHA-512withECDSA")
            .unwrap()
            .algorithm()
    );
    assert!(matches!(
        asn1.signer().get_by_name("SHA-256withNothing"),
        Err(AlgoAsn1Error::UnknownSigner)
    ));
}

// RFC 4055 section 5 asks a reader to accept RSA's NULL absent as well; PSS with another salt
// length is no row's
#[test]
fn rsa_reads_without_its_null_but_pss_only_with_the_parameters_of_a_row() {
    let asn1 = asn1();
    let bare = AlgorithmIdentifier::new("1.2.840.113549.1.1.11".parse().unwrap());
    let signer = asn1.signer().get_by_id(&bare).unwrap();
    assert_eq!(signer.algorithm(), &bare);

    let pss = AlgorithmIdentifier::new("1.2.840.113549.1.1.10".parse().unwrap());
    assert!(matches!(
        asn1.signer().get_by_id(&pss),
        Err(AlgoAsn1Error::UnknownSigner)
    ));
}

// Each certificate is self-signed: the signer its signature algorithm calls for, with the key its
// SPKI holds, verifies the signature over the TBS
#[test]
fn the_certificates_openssl_signed_with_each_algorithm_verify() {
    let asn1 = asn1();
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
        let (_, certificate) = Certificate::decode(file, &DecodingOptions::default()).unwrap();
        let key = asn1
            .spki()
            .decode(certificate.subject_public_key_info())
            .unwrap();
        let mut verifier = asn1
            .signer()
            .get_by_id(certificate.signature_algorithm())
            .unwrap();
        verifier.init(key.as_ref()).unwrap();
        verifier.update(certificate.tbs_raw()).unwrap();
        let signature = certificate.signature_value().as_bytes();
        assert!(verifier.verify_signature(signature).unwrap(), "{name}");
    }
}

#[test]
fn an_sm2_signature_made_under_its_row_verifies_and_a_changed_message_does_not() {
    let algo = algo();
    let asn1 = asn1();
    let mut generator = algo.key_pair_generator().get_by_name("EC").unwrap();
    generator
        .init(&EcKeyGenParams::from_oid(
            "1.2.156.10197.1.301".parse().unwrap(),
        ))
        .unwrap();
    let pair = generator.generate().unwrap();

    let mut signer = asn1.signer().get_by_name("SM3withSM2").unwrap();
    assert_eq!(
        signer.algorithm().algorithm().to_string(),
        "1.2.156.10197.1.501"
    );
    assert!(signer.algorithm().parameters().is_none());
    signer.init(pair.private()).unwrap();
    signer.update(b"message").unwrap();
    let signature = signer.sign().unwrap();

    let mut verifier = asn1.signer().get_by_id(signer.algorithm()).unwrap();
    verifier.init(pair.public()).unwrap();
    verifier.update(b"message").unwrap();
    assert!(verifier.verify_signature(&signature).unwrap());

    let mut verifier = asn1.signer().get_by_id(signer.algorithm()).unwrap();
    verifier.init(pair.public()).unwrap();
    verifier.update(b"massage").unwrap();
    assert!(!verifier.verify_signature(&signature).unwrap());
}
