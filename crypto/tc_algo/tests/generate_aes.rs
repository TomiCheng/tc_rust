#![cfg(feature = "aes")]

use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_algo::ErrorKind;
use tc_algo::generate::{self, KeyGenParams};
use tc_algo::params::{AnyKeyParams, AnyParams};

#[test]
fn each_aes_generator_makes_a_key_of_its_own_size() {
    for (name, bytes) in [("AES", 24), ("AES128", 16), ("AES192", 24), ("AES256", 32)] {
        let key = generate::get_key_generator(name)
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(key.key.len(), bytes, "{name}");
    }
}

#[test]
fn init_sets_one_of_the_three_aes_sizes() {
    let mut generator = generate::get_key_generator("AES").unwrap();
    generator
        .init(KeyGenParams::Strength { bits: 256 })
        .unwrap();
    assert_eq!(generator.generate().unwrap().key.len(), 32);
}

#[test]
fn init_refuses_a_size_aes_does_not_have_and_keeps_its_own() {
    let mut generator = generate::get_key_generator("AES").unwrap();
    let error = generator
        .init(KeyGenParams::Strength { bits: 100 })
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
    assert_eq!(generator.generate().unwrap().key.len(), 24);
}

#[test]
fn the_same_seed_gives_the_same_key_and_fresh_randomness_does_not() {
    let seeded = || {
        let mut generator = generate::get_key_generator("AES256").unwrap();
        generator
            .with_rng(StdRng::seed_from_u64(7))
            .generate()
            .unwrap()
    };
    assert_eq!(seeded().key, seeded().key);
    let fresh = || generate::generate_key("AES256").unwrap();
    assert_ne!(fresh().key, fresh().key);
}

#[test]
fn every_oid_of_a_size_finds_the_generator_of_that_size() {
    for entry in generate::key_generators() {
        for oid in entry.oids() {
            let generator = generate::get_key_generator_by_oid(&oid.oid()).unwrap();
            assert_eq!(generator.entry().name(), entry.name(), "{}", oid.dotted());
        }
    }
    let gcm = generate::get_key_generator("2.16.840.1.101.3.4.1.46").unwrap();
    assert_eq!(gcm.entry().name(), "AES256");
}

#[test]
fn names_match_without_regard_to_case_and_aeswrap_is_aes() {
    for name in ["AES", "aes", "AESWRAP", "aeswrap"] {
        let generator = generate::get_key_generator(name).unwrap();
        assert_eq!(generator.entry().name(), "AES");
    }
}

#[test]
fn an_unknown_name_is_reported_as_an_unknown_generator() {
    let error = generate::get_key_generator("no-such-key").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownGenerator);
}

#[test]
fn a_generated_key_goes_into_the_params_as_a_secret_key() {
    let key = generate::generate_key("AES128").unwrap();
    let params = AnyParams::new(AnyKeyParams::Secret(key));
    assert!(matches!(params.key, AnyKeyParams::Secret(_)));
}

#[test]
fn debug_shows_the_name_and_params_but_not_the_randomness() {
    let generator = generate::get_key_generator("AES").unwrap();
    assert_eq!(
        format!("{generator:?}"),
        "KeyGenerator { name: \"AES\", params: Some(Strength { bits: 192 }), .. }"
    );
}

#[test]
fn the_entry_shows_its_name_and_oids() {
    let entry = generate::key_generators()
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
    let mut generator = generate::get_key_generator("AES").unwrap();
    let error = generator.init(KeyGenParams::rsa()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
}
