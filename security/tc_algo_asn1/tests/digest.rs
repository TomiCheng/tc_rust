use tc_algo::{Algo, AlgoBuilder, DefaultAlgoBuilder};
use tc_algo_asn1::{AlgoAsn1, AlgoAsn1Builder, AlgoAsn1Error, DefaultAlgoAsn1Builder};
use tc_asn1::Asn1Object;
use tc_asn1_x509::alg::AlgorithmIdentifier;

fn algo() -> Box<dyn Algo> {
    DefaultAlgoBuilder::default().build()
}

fn asn1() -> Box<dyn AlgoAsn1> {
    DefaultAlgoAsn1Builder::default().build()
}

// Each row with its OID and whether it is written with a NULL
const ROWS: [(&str, &str, bool); 23] = [
    ("SHA-1", "1.3.14.3.2.26", true),
    ("SHA-224", "2.16.840.1.101.3.4.2.4", false),
    ("SHA-256", "2.16.840.1.101.3.4.2.1", false),
    ("SHA-384", "2.16.840.1.101.3.4.2.2", false),
    ("SHA-512", "2.16.840.1.101.3.4.2.3", false),
    ("SHA-512/224", "2.16.840.1.101.3.4.2.5", false),
    ("SHA-512/256", "2.16.840.1.101.3.4.2.6", false),
    ("SHA3-224", "2.16.840.1.101.3.4.2.7", false),
    ("SHA3-256", "2.16.840.1.101.3.4.2.8", false),
    ("SHA3-384", "2.16.840.1.101.3.4.2.9", false),
    ("SHA3-512", "2.16.840.1.101.3.4.2.10", false),
    ("SHAKE128-256", "2.16.840.1.101.3.4.2.11", false),
    ("SHAKE256-512", "2.16.840.1.101.3.4.2.12", false),
    ("GOST3411", "1.2.643.2.2.9", true),
    ("GOST3411-2012-256", "1.2.643.7.1.1.2.2", false),
    ("GOST3411-2012-512", "1.2.643.7.1.1.2.3", false),
    ("MD2", "1.2.840.113549.2.2", true),
    ("MD4", "1.2.840.113549.2.4", true),
    ("MD5", "1.2.840.113549.2.5", true),
    ("RIPEMD128", "1.3.36.3.2.2", true),
    ("RIPEMD160", "1.3.36.3.2.1", true),
    ("RIPEMD256", "1.3.36.3.2.3", true),
    ("SM3", "1.2.156.10197.1.401", false),
];

#[test]
fn every_row_writes_the_algorithm_identifier_of_bouncy_castle_and_hashes_as_tc_algo_does() {
    let algo = algo();
    let asn1 = asn1();
    for (name, oid, with_null) in ROWS {
        let mut digest = asn1.digest().get_by_name(name).unwrap();
        let algorithm = digest.algorithm().clone();
        assert_eq!(algorithm.algorithm().to_string(), oid, "{name}");
        assert_eq!(
            matches!(algorithm.parameters(), Some(Asn1Object::Null(_))),
            with_null,
            "{name}"
        );
        if !with_null {
            assert!(algorithm.parameters().is_none(), "{name}");
        }

        digest.try_update(b"abc").unwrap();
        let hash = digest.finalize().unwrap();
        assert_eq!(
            hash,
            algo.digest().calculate_by_name(name, b"abc").unwrap(),
            "{name}"
        );

        let mut again = asn1.digest().get_by_id(&algorithm).unwrap();
        again.try_update(b"abc").unwrap();
        assert_eq!(again.finalize().unwrap(), hash, "{name}");
    }
}

#[test]
fn sha_256_of_abc_is_the_fips_180_vector() {
    let mut digest = asn1().digest().get_by_name("sha256").unwrap();
    digest.try_update(b"abc").unwrap();
    let hash = digest.finalize().unwrap();
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, expected);
}

// RFC 8702: SHAKE128 as a digest gives 32 bytes, SHAKE256 64
#[test]
fn shake_as_a_digest_has_the_output_length_of_rfc_8702() {
    let asn1 = asn1();
    assert_eq!(
        asn1.digest().get_by_name("SHAKE128").unwrap().digest_size(),
        32
    );
    assert_eq!(
        asn1.digest().get_by_name("SHAKE256").unwrap().digest_size(),
        64
    );
}

// RFC 5754 section 2 asks a reader to accept the NULL present or absent; the digest keeps the
// AlgorithmIdentifier as it was read
#[test]
fn a_digest_reads_with_or_without_its_null_and_keeps_what_it_read() {
    let asn1 = asn1();
    let with_null = AlgorithmIdentifier::with_null("2.16.840.1.101.3.4.2.1".parse().unwrap());
    assert_eq!(
        asn1.digest().get_by_id(&with_null).unwrap().algorithm(),
        &with_null
    );

    let bare = AlgorithmIdentifier::new("1.3.14.3.2.26".parse().unwrap());
    assert_eq!(asn1.digest().get_by_id(&bare).unwrap().algorithm(), &bare);
}

#[test]
fn a_name_or_an_oid_no_row_has_is_an_unknown_digest() {
    let asn1 = asn1();
    assert!(matches!(
        asn1.digest().get_by_name("SHA-256withRSA"),
        Err(AlgoAsn1Error::UnknownDigest)
    ));
    let unknown = AlgorithmIdentifier::new("1.2.840.113549.1.1.11".parse().unwrap());
    assert!(matches!(
        asn1.digest().get_by_id(&unknown),
        Err(AlgoAsn1Error::UnknownDigest)
    ));
}

// Each signer row of the crate, with the OID of the digest CMS writes beside its signature
const SIGNERS: [(&str, &str); 22] = [
    ("SHA-1withRSA", "1.3.14.3.2.26"),
    ("SHA-224withRSA", "2.16.840.1.101.3.4.2.4"),
    ("SHA-256withRSA", "2.16.840.1.101.3.4.2.1"),
    ("SHA-384withRSA", "2.16.840.1.101.3.4.2.2"),
    ("SHA-512withRSA", "2.16.840.1.101.3.4.2.3"),
    ("SHA-1withRSAandMGF1", "1.3.14.3.2.26"),
    ("SHA-224withRSAandMGF1", "2.16.840.1.101.3.4.2.4"),
    ("SHA-256withRSAandMGF1", "2.16.840.1.101.3.4.2.1"),
    ("SHA-384withRSAandMGF1", "2.16.840.1.101.3.4.2.2"),
    ("SHA-512withRSAandMGF1", "2.16.840.1.101.3.4.2.3"),
    ("SHA-1withECDSA", "1.3.14.3.2.26"),
    ("SHA-224withECDSA", "2.16.840.1.101.3.4.2.4"),
    ("SHA-256withECDSA", "2.16.840.1.101.3.4.2.1"),
    ("SHA-384withECDSA", "2.16.840.1.101.3.4.2.2"),
    ("SHA-512withECDSA", "2.16.840.1.101.3.4.2.3"),
    ("Ed25519", "2.16.840.1.101.3.4.2.3"),
    ("Ed448", "2.16.840.1.101.3.4.2.18"),
    ("SHA-1withDSA", "1.3.14.3.2.26"),
    ("SHA-224withDSA", "2.16.840.1.101.3.4.2.4"),
    ("SHA-256withDSA", "2.16.840.1.101.3.4.2.1"),
    ("SM3withSM2", "1.2.156.10197.1.401"),
    ("SHA256withSM2", "2.16.840.1.101.3.4.2.1"),
];

#[test]
fn every_signer_row_finds_the_digest_it_hashes_with() {
    let asn1 = asn1();
    for (name, digest) in SIGNERS {
        let signer = asn1.signer().get_by_name(name).unwrap();
        let found = asn1.digest().get_by_signer(signer.algorithm()).unwrap();
        assert_eq!(found.algorithm().algorithm().to_string(), digest, "{name}");
    }
}

// RFC 8419: id-shake256-len with 512 bits, which reads back only with that length
#[test]
fn ed448_hashes_with_shake256_of_512_bits() {
    let asn1 = asn1();
    let signer = asn1.signer().get_by_name("Ed448").unwrap();
    let digest = asn1.digest().get_by_signer(signer.algorithm()).unwrap();
    assert_eq!(
        digest.algorithm().parameters(),
        Some(&Asn1Object::Integer(512u64.into()))
    );
    assert_eq!(digest.digest_size(), 64);
    assert!(asn1.digest().get_by_id(digest.algorithm()).is_ok());

    let shorter = AlgorithmIdentifier::with_parameters(
        "2.16.840.1.101.3.4.2.18".parse().unwrap(),
        Asn1Object::Integer(256u64.into()),
    );
    assert!(matches!(
        asn1.digest().get_by_id(&shorter),
        Err(AlgoAsn1Error::UnknownDigest)
    ));
}

// The digest is written as its row writes it, not as PSS carries it; PSS without parameters hashes
// with SHA-1, as RFC 4055 has it
#[test]
fn pss_gives_the_digest_of_its_parameters_as_the_row_writes_it() {
    let asn1 = asn1();
    let signer = asn1.signer().get_by_name("SHA-256withRSAandMGF1").unwrap();
    let digest = asn1.digest().get_by_signer(signer.algorithm()).unwrap();
    assert_eq!(
        digest.algorithm(),
        &AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap())
    );

    let bare = AlgorithmIdentifier::new("1.2.840.113549.1.1.10".parse().unwrap());
    let digest = asn1.digest().get_by_signer(&bare).unwrap();
    assert_eq!(digest.algorithm().algorithm().to_string(), "1.3.14.3.2.26");
}

#[test]
fn a_signature_algorithm_no_row_lists_is_an_unknown_digest() {
    let asn1 = asn1();
    let sha256 = AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap());
    assert!(matches!(
        asn1.digest().get_by_signer(&sha256),
        Err(AlgoAsn1Error::UnknownDigest)
    ));
}
