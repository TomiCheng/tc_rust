#![cfg(all(
    feature = "skein",
    feature = "esch",
    feature = "xoodyak",
    feature = "photon-beetle",
    feature = "ascon-hash256",
    feature = "ascon-hash-legacy",
    feature = "isap",
    feature = "haraka",
))]

// The digests that Bouncy Castle has as classes but not in its DigestUtilities, against digests its
// classes gave
#[path = "vectors/bc_digests.rs"]
mod bc_digests;

use std::sync::LazyLock;

use bc_digests::VECTORS;
use tc_algo_old::{Algo, TryDigest};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn every_digest_is_the_one_bouncy_castle_gave() {
    assert!(VECTORS.len() > 290);
    for &(name, message, expected) in VECTORS {
        let (message, expected) = (unhex(message), unhex(expected));
        let mut digest = ALGO
            .digest()
            .get_by_name(name)
            .unwrap_or_else(|_| panic!("{name}"));
        assert_eq!(TryDigest::digest_size(&digest), expected.len(), "{name}");
        for piece in message.chunks(7) {
            digest.update(piece);
        }
        assert_eq!(
            digest.finalize(),
            expected,
            "{name} over {} bytes",
            message.len()
        );
    }
}

#[test]
fn every_digest_has_a_vector_for_each_of_its_names() {
    for name in [
        "SKEIN-256-128",
        "SKEIN-256-160",
        "SKEIN-256-224",
        "SKEIN-256-256",
        "SKEIN-512-128",
        "SKEIN-512-160",
        "SKEIN-512-224",
        "SKEIN-512-256",
        "SKEIN-512-384",
        "SKEIN-512-512",
        "SKEIN-1024-384",
        "SKEIN-1024-512",
        "SKEIN-1024-1024",
        "ESCH-256",
        "ESCH-384",
        "XOODYAK",
        "PHOTON-BEETLE",
        "ASCON-HASH256",
        "ASCON-HASH",
        "ASCON-HASHA",
        "ISAP",
        "HARAKA-256",
        "HARAKA-512",
    ] {
        assert!(VECTORS.iter().any(|vector| vector.0 == name), "{name}");
    }
}

#[test]
fn the_short_names_find_the_same_digests() {
    for (alias, canonical) in [
        ("XOODYAK HASH", "XOODYAK"),
        ("PHOTON-BEETLE HASH", "PHOTON-BEETLE"),
        ("ISAP HASH", "ISAP"),
        ("skein-512-256", "SKEIN-512-256"),
        ("esch-256", "ESCH-256"),
        ("haraka-256", "HARAKA-256"),
    ] {
        assert_eq!(
            ALGO.digest().get_by_name(alias).unwrap().entry().name(),
            canonical
        );
    }
}

#[test]
fn finalize_starts_the_next_message_for_every_digest_here() {
    for &(name, message, expected) in VECTORS {
        let (message, expected) = (unhex(message), unhex(expected));
        let mut digest = ALGO.digest().get_by_name(name).unwrap();
        digest.update(&message);
        digest.finalize();
        digest.update(&message);
        assert_eq!(digest.finalize(), expected, "{name}");
    }
}

#[test]
#[should_panic(expected = "HARAKA-256 takes exactly 32 bytes and HARAKA-512 exactly 64")]
fn haraka_panics_on_an_input_that_is_too_long() {
    let mut haraka = ALGO.digest().get_by_name("HARAKA-256").unwrap();
    haraka.update(&[0; 33]);
}

#[test]
#[should_panic(expected = "HARAKA-256 takes exactly 32 bytes and HARAKA-512 exactly 64")]
fn haraka_panics_on_an_input_that_is_too_short() {
    let mut haraka = ALGO.digest().get_by_name("HARAKA-512").unwrap();
    haraka.update(&[0; 63]);
    haraka.finalize();
}
