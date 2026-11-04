#![allow(deprecated, reason = "the legacy Ascon digests have rows too")]

use std::collections::HashSet;

use tc_algo::digest;
#[allow(unused_imports, reason = "unused when every digest feature is off")]
use tc_algo::digest::{Digest, TryDigest};

// Longer than any block size here, so the multi-block path is exercised too
const INPUT: [u8; 300] = {
    let mut input = [0; 300];
    let mut i = 0;
    while i < input.len() {
        input[i] = i as u8;
        i += 1;
    }
    input
};

#[allow(dead_code, reason = "unused when every digest feature is off")]
fn hash_with<D: Digest>(mut digest: D) -> Vec<u8> {
    digest.update(&INPUT);
    let mut output = vec![0; digest.digest_size()];
    let written = digest.do_final(&mut output);
    output.truncate(written);
    output
}

struct Case {
    name: &'static str,
    size: usize,
    expected: Vec<u8>,
}

// Built from the underlying crates directly, independently of the factory table
fn cases() -> Vec<Case> {
    #[allow(unused_mut, reason = "stays empty when every digest feature is off")]
    let mut cases = Vec::new();
    #[allow(unused_macros, reason = "unused when every digest feature is off")]
    macro_rules! case {
        ($name:literal, $size:literal, $digest:expr) => {
            cases.push(Case {
                name: $name,
                size: $size,
                expected: hash_with($digest),
            })
        };
    }
    #[cfg(feature = "md2")]
    case!("MD2", 16, tc_md::Md2Digest::new());
    #[cfg(feature = "md4")]
    case!("MD4", 16, tc_md::Md4Digest::new());
    #[cfg(feature = "md5")]
    case!("MD5", 16, tc_md::Md5Digest::new());
    #[cfg(feature = "sha1")]
    case!("SHA-1", 20, tc_sha::Sha1Digest::new());
    #[cfg(feature = "sha224")]
    case!("SHA-224", 28, tc_sha::Sha224Digest::new());
    #[cfg(feature = "sha256")]
    case!("SHA-256", 32, tc_sha::Sha256Digest::new());
    #[cfg(feature = "sha384")]
    case!("SHA-384", 48, tc_sha::Sha384Digest::new());
    #[cfg(feature = "sha512")]
    case!("SHA-512", 64, tc_sha::Sha512Digest::new());
    #[cfg(feature = "sha512-224")]
    case!("SHA-512/224", 28, tc_sha::Sha512tDigest::new(224));
    #[cfg(feature = "sha512-256")]
    case!("SHA-512/256", 32, tc_sha::Sha512tDigest::new(256));
    #[cfg(feature = "sha3-224")]
    case!("SHA3-224", 28, tc_keccak::Sha3Digest::new(224));
    #[cfg(feature = "sha3-256")]
    case!("SHA3-256", 32, tc_keccak::Sha3Digest::new(256));
    #[cfg(feature = "sha3-384")]
    case!("SHA3-384", 48, tc_keccak::Sha3Digest::new(384));
    #[cfg(feature = "sha3-512")]
    case!("SHA3-512", 64, tc_keccak::Sha3Digest::new(512));
    #[cfg(feature = "keccak-224")]
    case!("KECCAK-224", 28, tc_keccak::KeccakDigest::new(224));
    #[cfg(feature = "keccak-256")]
    case!("KECCAK-256", 32, tc_keccak::KeccakDigest::new(256));
    #[cfg(feature = "keccak-288")]
    case!("KECCAK-288", 36, tc_keccak::KeccakDigest::new(288));
    #[cfg(feature = "keccak-384")]
    case!("KECCAK-384", 48, tc_keccak::KeccakDigest::new(384));
    #[cfg(feature = "keccak-512")]
    case!("KECCAK-512", 64, tc_keccak::KeccakDigest::new(512));
    #[cfg(feature = "shake128")]
    case!("SHAKE128-256", 32, tc_keccak::ShakeDigest::new(128));
    #[cfg(feature = "shake256")]
    case!("SHAKE256-512", 64, tc_keccak::ShakeDigest::new(256));
    #[cfg(feature = "blake2b-160")]
    case!(
        "BLAKE2B-160",
        20,
        tc_blake::Blake2bDigest::with_digest_size(160)
    );
    #[cfg(feature = "blake2b-256")]
    case!(
        "BLAKE2B-256",
        32,
        tc_blake::Blake2bDigest::with_digest_size(256)
    );
    #[cfg(feature = "blake2b-384")]
    case!(
        "BLAKE2B-384",
        48,
        tc_blake::Blake2bDigest::with_digest_size(384)
    );
    #[cfg(feature = "blake2b-512")]
    case!(
        "BLAKE2B-512",
        64,
        tc_blake::Blake2bDigest::with_digest_size(512)
    );
    #[cfg(feature = "blake2s-128")]
    case!(
        "BLAKE2S-128",
        16,
        tc_blake::Blake2sDigest::with_digest_size(128)
    );
    #[cfg(feature = "blake2s-160")]
    case!(
        "BLAKE2S-160",
        20,
        tc_blake::Blake2sDigest::with_digest_size(160)
    );
    #[cfg(feature = "blake2s-224")]
    case!(
        "BLAKE2S-224",
        28,
        tc_blake::Blake2sDigest::with_digest_size(224)
    );
    #[cfg(feature = "blake2s-256")]
    case!(
        "BLAKE2S-256",
        32,
        tc_blake::Blake2sDigest::with_digest_size(256)
    );
    #[cfg(feature = "blake3-256")]
    case!(
        "BLAKE3-256",
        32,
        tc_blake::Blake3Digest::with_digest_size(256)
    );
    #[cfg(feature = "dstu7564-256")]
    case!("DSTU7564-256", 32, tc_dstu7564::Dstu7564Digest::new(256));
    #[cfg(feature = "dstu7564-384")]
    case!("DSTU7564-384", 48, tc_dstu7564::Dstu7564Digest::new(384));
    #[cfg(feature = "dstu7564-512")]
    case!("DSTU7564-512", 64, tc_dstu7564::Dstu7564Digest::new(512));
    #[cfg(feature = "gost3411")]
    case!("GOST3411", 32, tc_gost3411::Gost3411Digest::new());
    #[cfg(feature = "gost3411-2012-256")]
    case!(
        "GOST3411-2012-256",
        32,
        tc_gost3411::Gost3411_2012_256Digest::new()
    );
    #[cfg(feature = "gost3411-2012-512")]
    case!(
        "GOST3411-2012-512",
        64,
        tc_gost3411::Gost3411_2012_512Digest::new()
    );
    #[cfg(feature = "ripemd128")]
    case!("RIPEMD128", 16, tc_ripemd::RipeMd128Digest::new());
    #[cfg(feature = "ripemd160")]
    case!("RIPEMD160", 20, tc_ripemd::RipeMd160Digest::new());
    #[cfg(feature = "ripemd256")]
    case!("RIPEMD256", 32, tc_ripemd::RipeMd256Digest::new());
    #[cfg(feature = "ripemd320")]
    case!("RIPEMD320", 40, tc_ripemd::RipeMd320Digest::new());
    #[cfg(feature = "sm3")]
    case!("SM3", 32, tc_sm3::Sm3Digest::new());
    #[cfg(feature = "tiger")]
    case!("TIGER", 24, tc_misc_digest::TigerDigest::new());
    #[cfg(feature = "whirlpool")]
    case!("WHIRLPOOL", 64, tc_misc_digest::WhirlpoolDigest::new());
    // NONE's size is the number of bytes taken so far, so a fresh one reports 0
    #[cfg(feature = "skein-256-128")]
    case!("SKEIN-256-128", 16, tc_skein::SkeinDigest::new(256, 128));
    #[cfg(feature = "skein-256-160")]
    case!("SKEIN-256-160", 20, tc_skein::SkeinDigest::new(256, 160));
    #[cfg(feature = "skein-256-224")]
    case!("SKEIN-256-224", 28, tc_skein::SkeinDigest::new(256, 224));
    #[cfg(feature = "skein-256-256")]
    case!("SKEIN-256-256", 32, tc_skein::SkeinDigest::new(256, 256));
    #[cfg(feature = "skein-512-128")]
    case!("SKEIN-512-128", 16, tc_skein::SkeinDigest::new(512, 128));
    #[cfg(feature = "skein-512-160")]
    case!("SKEIN-512-160", 20, tc_skein::SkeinDigest::new(512, 160));
    #[cfg(feature = "skein-512-224")]
    case!("SKEIN-512-224", 28, tc_skein::SkeinDigest::new(512, 224));
    #[cfg(feature = "skein-512-256")]
    case!("SKEIN-512-256", 32, tc_skein::SkeinDigest::new(512, 256));
    #[cfg(feature = "skein-512-384")]
    case!("SKEIN-512-384", 48, tc_skein::SkeinDigest::new(512, 384));
    #[cfg(feature = "skein-512-512")]
    case!("SKEIN-512-512", 64, tc_skein::SkeinDigest::new(512, 512));
    #[cfg(feature = "skein-1024-384")]
    case!("SKEIN-1024-384", 48, tc_skein::SkeinDigest::new(1024, 384));
    #[cfg(feature = "skein-1024-512")]
    case!("SKEIN-1024-512", 64, tc_skein::SkeinDigest::new(1024, 512));
    #[cfg(feature = "skein-1024-1024")]
    case!(
        "SKEIN-1024-1024",
        128,
        tc_skein::SkeinDigest::new(1024, 1024)
    );
    #[cfg(feature = "esch-256")]
    case!(
        "ESCH-256",
        32,
        tc_misc_digest::SparkleDigest::new(tc_misc_digest::SparkleParameters::Esch256)
    );
    #[cfg(feature = "esch-384")]
    case!(
        "ESCH-384",
        48,
        tc_misc_digest::SparkleDigest::new(tc_misc_digest::SparkleParameters::Esch384)
    );
    #[cfg(feature = "xoodyak")]
    case!("XOODYAK", 32, tc_misc_digest::XoodyakDigest::new());
    #[cfg(feature = "photon-beetle")]
    case!(
        "PHOTON-BEETLE",
        32,
        tc_misc_digest::PhotonBeetleDigest::new()
    );
    #[cfg(feature = "ascon-hash256")]
    case!("ASCON-HASH256", 32, tc_ascon_hash::AsconHash256::new());
    #[cfg(feature = "ascon-hash-legacy")]
    case!(
        "ASCON-HASH",
        32,
        tc_ascon_hash::AsconDigest::new(tc_ascon_hash::AsconParameters::AsconHash)
    );
    #[cfg(feature = "ascon-hash-legacy")]
    case!(
        "ASCON-HASHA",
        32,
        tc_ascon_hash::AsconDigest::new(tc_ascon_hash::AsconParameters::AsconHashA)
    );
    #[cfg(feature = "isap")]
    case!("ISAP", 32, tc_ascon_hash::IsapDigest::new());
    #[cfg(feature = "null-digest")]
    case!("NONE", 0, tc_digest::util::NullDigest::new());
    cases
}

#[test]
fn every_enabled_digest_has_its_canonical_name_size_and_output() {
    for case in cases() {
        let mut digest = digest::get_by_name(case.name).unwrap();
        assert_eq!(digest.entry().name(), case.name);
        assert_eq!(digest.digest_size(), case.size, "{}", case.name);
        digest.update(&INPUT);
        assert_eq!(digest.finalize(), case.expected, "{}", case.name);
    }
}

#[test]
fn the_table_lists_every_enabled_digest_exactly_once() {
    let listed: Vec<&str> = digest::algorithms().map(|entry| entry.name()).collect();
    let unique: HashSet<&str> = listed.iter().copied().collect();
    assert_eq!(listed.len(), unique.len());
    // Haraka takes an input of its own, so it has its tests elsewhere
    let haraka = listed.iter().filter(|name| name.starts_with("HARAKA-"));
    assert_eq!(listed.len() - haraka.count(), cases().len());
}

#[test]
fn no_two_entries_share_a_name_or_an_oid() {
    let mut names = HashSet::new();
    let mut oids = HashSet::new();
    for entry in digest::algorithms() {
        assert!(
            names.insert(entry.name().to_ascii_uppercase()),
            "{}",
            entry.name()
        );
        for oid in entry.oids() {
            assert!(oids.insert(oid.dotted()), "{}", oid.dotted());
        }
    }
}

#[test]
fn every_name_and_oid_of_an_entry_finds_that_entry() {
    for entry in digest::algorithms() {
        let by_name = digest::get_by_name(entry.name()).unwrap();
        assert_eq!(by_name.entry(), entry);
        for oid in entry.oids() {
            let by_oid = digest::get_by_oid(&oid.oid()).unwrap();
            assert_eq!(by_oid.entry(), entry, "{}", oid.dotted());
        }
    }
}

#[test]
fn only_the_digests_bouncy_castle_gives_no_oid_lack_one() {
    for entry in digest::algorithms() {
        let name = entry.name();
        let without_oid = ["KECCAK-", "SKEIN-", "ESCH-", "ASCON-", "HARAKA-"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
            || [
                "RIPEMD320",
                "TIGER",
                "WHIRLPOOL",
                "NONE",
                "XOODYAK",
                "PHOTON-BEETLE",
                "ISAP",
            ]
            .contains(&name);
        assert_eq!(entry.oid().is_none(), without_oid, "{name}");
    }
}

#[test]
fn the_ripemd_aliases_with_a_hyphen_find_the_same_digests() {
    for (alias, canonical) in [
        ("RIPEMD-128", "RIPEMD128"),
        ("RIPEMD-160", "RIPEMD160"),
        ("RIPEMD-256", "RIPEMD256"),
        ("RIPEMD-320", "RIPEMD320"),
    ] {
        if let Ok(by_canonical) = digest::get_by_name(canonical) {
            let by_alias = digest::get_by_name(alias).unwrap();
            assert_eq!(by_alias.entry(), by_canonical.entry(), "{alias}");
        }
    }
}

#[cfg(feature = "null-digest")]
#[test]
fn none_passes_the_message_through_unchanged() {
    assert_eq!(digest::calculate_by_name("NONE", b"abc").unwrap(), b"abc");
    let mut output = [0; 3];
    assert_eq!(
        digest::calculate_by_name_into("NONE", b"abc", &mut output).unwrap(),
        3
    );
    assert_eq!(&output, b"abc");
}

#[cfg(feature = "null-digest")]
#[test]
#[should_panic(expected = "output is shorter than the digest")]
fn calculate_into_with_none_panics_when_the_output_is_shorter_than_the_message() {
    digest::calculate_by_name_into("NONE", b"abc", &mut [0; 2]).unwrap();
}
