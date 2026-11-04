#![cfg(feature = "sha256")]

use std::sync::LazyLock;

use tc_algo::{Algo, AnyDigest, Digest, DigestEntry, ErrorKind, TryDigest};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

// FIPS 180-2, appendix B.1
const ABC_SHA256: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

fn sha256() -> AnyDigest {
    ALGO.digest().get_by_name("SHA-256").unwrap()
}

fn sha256_entry() -> &'static DigestEntry {
    sha256().entry()
}

#[test]
fn sha256_of_abc_matches_the_fips_180_vector() {
    assert_eq!(
        ALGO.digest().calculate_by_name("SHA-256", b"abc").unwrap(),
        ABC_SHA256
    );
}

#[test]
fn update_in_pieces_gives_the_same_hash_as_one_update() {
    let mut sha256 = sha256();
    sha256.update(b"a");
    sha256.update(b"bc");
    assert_eq!(sha256.finalize(), ABC_SHA256);
}

#[test]
fn finalize_resets_the_digest_for_the_next_message() {
    let mut sha256 = sha256();
    sha256.update(b"abc");
    sha256.finalize();
    sha256.update(b"abc");
    assert_eq!(sha256.finalize(), ABC_SHA256);
}

#[test]
fn a_clone_continues_independently_of_the_original() {
    let mut original = sha256();
    original.update(b"a");
    let mut copy = original.clone();
    original.update(b"bc");
    copy.update(b"bx");
    assert_eq!(original.finalize(), ABC_SHA256);
    assert_ne!(copy.finalize(), ABC_SHA256);
}

#[test]
fn the_trait_path_writes_the_same_hash_as_finalize() {
    let mut sha256 = sha256();
    sha256.update(b"abc");
    let mut output = [0; 32];
    assert_eq!(Digest::do_final(&mut sha256, &mut output), 32);
    assert_eq!(output, ABC_SHA256);
    assert_eq!(sha256.digest_size(), 32);
}

#[test]
fn names_match_without_regard_to_case_and_aliases_resolve() {
    for name in ["SHA-256", "sha-256", "SHA256", "sha256"] {
        assert_eq!(
            ALGO.digest().get_by_name(name).unwrap().entry(),
            sha256_entry()
        );
    }
}

#[test]
fn a_dotted_oid_is_accepted_where_a_name_is_expected() {
    let sha256 = ALGO.digest().get_by_name("2.16.840.1.101.3.4.2.1").unwrap();
    assert_eq!(sha256.entry(), sha256_entry());
}

#[test]
fn every_oid_of_the_entry_finds_the_same_digest() {
    for oid in sha256_entry().oids() {
        let sha256 = ALGO.digest().get_by_oid(&oid.oid()).unwrap();
        assert_eq!(sha256.entry(), sha256_entry());
    }
}

#[test]
fn an_unknown_name_is_reported_as_an_unknown_digest() {
    let error = ALGO.digest().get_by_name("no-such-digest").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownDigest);
    assert!(
        ALGO.digest()
            .calculate_by_name("no-such-digest", b"abc")
            .is_err()
    );
}

#[test]
fn the_entry_reports_the_canonical_name_and_the_digest_oid_first() {
    let entry = sha256_entry();
    assert_eq!(entry.name(), "SHA-256");
    assert_eq!(entry.oid().unwrap().dotted(), "2.16.840.1.101.3.4.2.1");
    assert_eq!(entry.to_string(), "SHA-256  [id-sha256, id-hmacWithSHA256]");
}

#[test]
fn the_algorithm_list_includes_sha256() {
    assert!(
        ALGO.digest()
            .algorithms()
            .any(|entry| entry == sha256_entry())
    );
}

#[test]
fn the_lookups_by_name_and_oid_calculate_the_same_hash() {
    let oid = sha256_entry().oid().unwrap().oid();
    assert_eq!(
        ALGO.digest().calculate_by_name("SHA-256", b"abc").unwrap(),
        ABC_SHA256
    );
    assert_eq!(
        ALGO.digest().calculate_by_oid(&oid, b"abc").unwrap(),
        ABC_SHA256
    );
}

#[test]
fn calculate_into_writes_the_hash_at_the_front_and_returns_its_length() {
    let mut output = [0xff; 40];
    assert_eq!(
        ALGO.digest()
            .calculate_by_name_into("SHA-256", b"abc", &mut output)
            .unwrap(),
        32
    );
    assert_eq!(output[..32], ABC_SHA256);
    assert_eq!(output[32..], [0xff; 8]);
}

#[test]
fn the_into_lookups_by_name_and_oid_write_the_same_hash() {
    let oid = sha256_entry().oid().unwrap().oid();
    let mut output = [0; 32];
    assert_eq!(
        ALGO.digest()
            .calculate_by_name_into("SHA-256", b"abc", &mut output)
            .unwrap(),
        32
    );
    assert_eq!(output, ABC_SHA256);
    output = [0; 32];
    assert_eq!(
        ALGO.digest()
            .calculate_by_oid_into(&oid, b"abc", &mut output)
            .unwrap(),
        32
    );
    assert_eq!(output, ABC_SHA256);
}

#[test]
#[should_panic(expected = "output is shorter than the digest")]
fn calculate_into_panics_when_the_output_is_shorter_than_the_digest() {
    ALGO.digest()
        .calculate_by_name_into("SHA-256", b"abc", &mut [0; 31])
        .unwrap();
}

#[test]
fn debug_shows_only_the_name_and_display_the_canonical_name() {
    let digest = sha256();
    assert_eq!(format!("{digest:?}"), "AnyDigest { name: \"SHA-256\", .. }");
    assert_eq!(digest.to_string(), "SHA-256");
}

#[test]
fn any_digest_can_be_cloned_and_sent_between_threads() {
    fn assert_traits<T: Digest + Clone + Send + Sync + 'static>() {}
    assert_traits::<AnyDigest>();
}
