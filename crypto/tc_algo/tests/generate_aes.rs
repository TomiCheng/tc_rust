#![cfg(feature = "aes")]

use std::sync::LazyLock;

use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_algo::{Algo, AnyKeyParams, AnyParams, ErrorKind, KeyGenParams};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

#[test]
fn each_aes_generator_makes_a_key_of_its_own_size() {
    for (name, bytes) in [("AES", 24), ("AES128", 16), ("AES192", 24), ("AES256", 32)] {
        let key = ALGO
            .key_generator()
            .get_by_name(name)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(key.key.len(), bytes, "{name}");
    }
}

#[test]
fn init_sets_one_of_the_three_aes_sizes() {
    let mut generator = ALGO.key_generator().get_by_name("AES").unwrap();
    generator
        .init(KeyGenParams::Strength { bits: 256 })
        .unwrap();
    assert_eq!(generator.generate().unwrap().key.len(), 32);
}

#[test]
fn init_refuses_a_size_aes_does_not_have_and_keeps_its_own() {
    let mut generator = ALGO.key_generator().get_by_name("AES").unwrap();
    let error = generator
        .init(KeyGenParams::Strength { bits: 100 })
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
    assert_eq!(generator.generate().unwrap().key.len(), 24);
}

#[test]
fn the_same_seed_gives_the_same_key_and_fresh_randomness_does_not() {
    let seeded = || {
        let mut generator = ALGO.key_generator().get_by_name("AES256").unwrap();
        generator
            .with_rng(StdRng::seed_from_u64(7))
            .generate()
            .unwrap()
    };
    assert_eq!(seeded().key, seeded().key);
    let fresh = || ALGO.key_generator().generate("AES256").unwrap();
    assert_ne!(fresh().key, fresh().key);
}

#[test]
fn every_oid_of_a_size_finds_the_generator_of_that_size() {
    for entry in ALGO.key_generator().algorithms() {
        for oid in entry.oids() {
            let generator = ALGO.key_generator().get_by_oid(&oid.oid()).unwrap();
            assert_eq!(generator.entry().name(), entry.name(), "{}", oid.dotted());
        }
    }
    let gcm = ALGO
        .key_generator()
        .get_by_name("2.16.840.1.101.3.4.1.46")
        .unwrap();
    assert_eq!(gcm.entry().name(), "AES256");
}

#[test]
fn names_match_without_regard_to_case_and_aeswrap_is_aes() {
    for name in ["AES", "aes", "AESWRAP", "aeswrap"] {
        let generator = ALGO.key_generator().get_by_name(name).unwrap();
        assert_eq!(generator.entry().name(), "AES");
    }
}

#[test]
fn an_unknown_name_is_reported_as_an_unknown_generator() {
    let error = ALGO.key_generator().get_by_name("no-such-key").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownGenerator);
}

#[test]
fn a_generated_key_goes_into_the_params_as_a_secret_key() {
    let key = ALGO.key_generator().generate("AES128").unwrap();
    let params = AnyParams::new(AnyKeyParams::Secret(key));
    assert!(matches!(params.key, AnyKeyParams::Secret(_)));
}

#[test]
fn debug_shows_the_name_and_params_but_not_the_randomness() {
    let generator = ALGO.key_generator().get_by_name("AES").unwrap();
    assert_eq!(
        format!("{generator:?}"),
        "KeyGenerator { name: \"AES\", params: Some(Strength { bits: 192 }), .. }"
    );
}

#[test]
fn the_entry_shows_its_name_and_oids() {
    let entry = ALGO
        .key_generator()
        .algorithms()
        .find(|entry| entry.name() == "AES128")
        .unwrap();
    assert!(
        entry
            .to_string()
            .starts_with("AES128  [id-aes128-ECB, id-aes128-CBC,")
    );
}

#[cfg(feature = "rsa")]
#[test]
fn aes_refuses_the_params_of_another_algorithm() {
    let mut generator = ALGO.key_generator().get_by_name("AES").unwrap();
    let error = generator.init(KeyGenParams::rsa()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
}
