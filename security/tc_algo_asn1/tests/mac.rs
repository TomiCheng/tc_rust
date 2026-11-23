use tc_algo::params::key::KeyOwned;
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

// Each row with the name of Bouncy Castle's finder, its OID and whether it is written with a NULL
const ROWS: [(&str, &str, &str, bool); 11] = [
    ("HMAC-SHA1", "HMACSHA1", "1.3.14.3.2.26", false),
    ("HMAC-SHA224", "HMACSHA224", "1.2.840.113549.2.8", true),
    ("HMAC-SHA256", "HMACSHA256", "1.2.840.113549.2.9", true),
    ("HMAC-SHA384", "HMACSHA384", "1.2.840.113549.2.10", true),
    ("HMAC-SHA512", "HMACSHA512", "1.2.840.113549.2.11", true),
    (
        "HMAC-SHA512-224",
        "HMACSHA512-224",
        "1.2.840.113549.2.12",
        true,
    ),
    (
        "HMAC-SHA512-256",
        "HMACSHA512-256",
        "1.2.840.113549.2.13",
        true,
    ),
    (
        "HMAC-SHA3-224",
        "HMACSHA3-224",
        "2.16.840.1.101.3.4.2.13",
        false,
    ),
    (
        "HMAC-SHA3-256",
        "HMACSHA3-256",
        "2.16.840.1.101.3.4.2.14",
        false,
    ),
    (
        "HMAC-SHA3-384",
        "HMACSHA3-384",
        "2.16.840.1.101.3.4.2.15",
        false,
    ),
    (
        "HMAC-SHA3-512",
        "HMACSHA3-512",
        "2.16.840.1.101.3.4.2.16",
        false,
    ),
];

#[test]
fn every_row_writes_the_algorithm_identifier_of_bouncy_castle_and_tags_as_tc_algo_does() {
    let algo = algo();
    let asn1 = asn1();
    let key = KeyOwned::new(vec![0x0b; 32]);
    for (name, bc_name, oid, with_null) in ROWS {
        let mut mac = asn1.mac().get_by_name(bc_name).unwrap();
        let algorithm = mac.algorithm().clone();
        assert_eq!(algorithm.algorithm().to_string(), oid, "{name}");
        if with_null {
            assert!(
                matches!(algorithm.parameters(), Some(Asn1Object::Null(_))),
                "{name}"
            );
        } else {
            assert!(algorithm.parameters().is_none(), "{name}");
        }

        mac.init(&key).unwrap();
        mac.update(b"message").unwrap();
        let tag = mac.finalize().unwrap();
        assert_eq!(
            tag,
            algo.mac()
                .calculate_by_name(name, &key, b"message")
                .unwrap(),
            "{name}"
        );

        let mut again = asn1.mac().get_by_id(&algorithm).unwrap();
        again.init(&key).unwrap();
        again.update(b"message").unwrap();
        assert!(again.verify(&tag).unwrap(), "{name}");
    }
}

// RFC 4231 test case 1
#[test]
fn hmac_sha256_gives_the_tag_of_rfc_4231() {
    let mut mac = asn1().mac().get_by_name("hmac-sha256").unwrap();
    mac.init(&KeyOwned::new(vec![0x0b; 20])).unwrap();
    mac.update(b"Hi There").unwrap();
    let hex: String = mac
        .finalize()
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hex,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn a_changed_message_does_not_verify() {
    let asn1 = asn1();
    let key = KeyOwned::new(vec![0x0b; 32]);
    let mut mac = asn1.mac().get_by_name("HMAC-SHA256").unwrap();
    mac.init(&key).unwrap();
    mac.update(b"message").unwrap();
    let tag = mac.finalize().unwrap();

    mac.update(b"massage").unwrap();
    assert!(!mac.verify(&tag).unwrap());
}

// HMAC-SHA1 is written as the OID of SHA-1, and read as well by hmacWithSHA1 of PKCS#5 and that of
// RFC 2104; the MAC keeps what it read
#[test]
fn hmac_sha1_reads_by_each_of_its_three_oids() {
    let asn1 = asn1();
    for oid in ["1.3.14.3.2.26", "1.2.840.113549.2.7", "1.3.6.1.5.5.8.1.2"] {
        let algorithm = AlgorithmIdentifier::with_null(oid.parse().unwrap());
        let mac = asn1.mac().get_by_id(&algorithm).unwrap();
        assert_eq!(mac.algorithm(), &algorithm, "{oid}");
        assert_eq!(mac.mac_size(), 20, "{oid}");
    }
}

// RFC 4231 section 3.1 asks a reader to accept the NULL present or absent
#[test]
fn hmac_sha256_reads_without_its_null() {
    let bare = AlgorithmIdentifier::new("1.2.840.113549.2.9".parse().unwrap());
    assert_eq!(asn1().mac().get_by_id(&bare).unwrap().algorithm(), &bare);
}

#[test]
fn a_name_or_an_oid_no_row_has_is_an_unknown_mac() {
    let asn1 = asn1();
    assert!(matches!(
        asn1.mac().get_by_name("SHA-256"),
        Err(AlgoAsn1Error::UnknownMac)
    ));
    let sha256 = AlgorithmIdentifier::new("2.16.840.1.101.3.4.2.1".parse().unwrap());
    assert!(matches!(
        asn1.mac().get_by_id(&sha256),
        Err(AlgoAsn1Error::UnknownMac)
    ));
}
