#![cfg(feature = "rsa")]

use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_algo::ErrorKind;
use tc_algo::generate::key_pair::KeyPair;
use tc_algo::generate::{self, KeyGenParams, RsaKeyGenParams};
use tc_algo::params::{AnyPrivateKey, AnyPublicKey};
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_rsa::{RsaKey, RsaKeyParams};

// Small keys keep the tests quick; the size is what is checked, not its strength
fn small_rsa() -> RsaKeyGenParams {
    KeyGenParams::rsa().with_bits(512).with_certainty(20)
}

fn rsa_keys(pair: &KeyPair) -> (&RsaKey, &RsaKey) {
    let (AnyPublicKey::Rsa(public), AnyPrivateKey::Rsa(private)) = (&pair.public, &pair.private)
    else {
        panic!("not an RSA key pair");
    };
    (public, private)
}

fn modulus(key: &RsaKey) -> &PaddedBigUint {
    RsaKeyParams::modulus(key)
}

#[test]
fn an_rsa_key_pair_has_the_size_asked_for_and_one_modulus() {
    let mut generator = generate::key_pair::get_by_name("RSA").unwrap();
    generator.init(small_rsa()).unwrap();
    let pair = generator.generate().unwrap();
    let (public, private) = rsa_keys(&pair);
    assert!(!public.is_private_key());
    assert!(private.is_private_key());
    assert_eq!(modulus(public).bits(), 512);
    assert_eq!(modulus(public), modulus(private));
}

#[test]
fn the_size_alone_keeps_the_default_exponent() {
    let mut generator = generate::key_pair::get_by_name("RSA").unwrap();
    generator
        .init(KeyGenParams::Strength { bits: 512 })
        .unwrap();
    let pair = generator.generate().unwrap();
    let (public, _) = rsa_keys(&pair);
    assert_eq!(
        *RsaKeyParams::exponent(public),
        PaddedBigUint::from(65537u32)
    );
}

#[test]
fn the_same_seed_gives_the_same_key_pair() {
    let generate = || {
        let mut generator = generate::key_pair::get_by_name("RSA").unwrap();
        generator.init(small_rsa()).unwrap();
        generator
            .with_rng(StdRng::seed_from_u64(7))
            .generate()
            .unwrap()
    };
    let (first, second) = (generate(), generate());
    assert_eq!(modulus(rsa_keys(&first).0), modulus(rsa_keys(&second).0));
}

#[test]
fn without_init_the_generator_uses_bouncy_castles_defaults() {
    let generator = generate::key_pair::get_by_name("RSA").unwrap();
    assert_eq!(
        format!("{generator:?}"),
        "KeyPairGenerator { name: \"RSA\", params: Some(Rsa(RsaKeyGenParams { public_exponent: \
         65537, bits: 2048, certainty: 100 })), .. }"
    );
}

#[test]
fn the_generator_is_found_by_name_alias_case_or_oid() {
    for name in ["RSA", "rsa", "1.2.840.113549.1.1.1"] {
        let generator = generate::key_pair::get_by_name(name).unwrap();
        assert_eq!(generator.entry().name(), "RSA");
    }
    let oid = generate::key_pair::algorithms()
        .find(|entry| entry.name() == "RSA")
        .unwrap()
        .oids()[0]
        .oid();
    assert!(generate::key_pair::get_by_oid(&oid).is_ok());
}

#[test]
fn an_unknown_name_is_reported_as_an_unknown_generator() {
    let error = generate::key_pair::get_by_name("no-such-generator").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownGenerator);
}

#[test]
fn a_size_rsa_cannot_take_is_reported_with_the_rsa_error_underneath() {
    let mut generator = generate::key_pair::get_by_name("RSA").unwrap();
    generator.init(KeyGenParams::Strength { bits: 8 }).unwrap();
    let error = generator.generate().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
    assert!(core::error::Error::source(&error).is_some());
}

#[cfg(feature = "ec")]
#[test]
fn init_rejects_params_of_another_algorithm_and_keeps_its_own() {
    let mut generator = generate::key_pair::get_by_name("RSA").unwrap();
    let ec = KeyGenParams::ec(tc_algo::params::EcCurve::Secp256r1);
    let error = generator.init(ec).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
    assert!(format!("{generator:?}").contains("bits: 2048"));
}

#[test]
fn the_entry_shows_its_name_and_oid() {
    let entry = generate::key_pair::algorithms()
        .find(|entry| entry.name() == "RSA")
        .unwrap();
    assert_eq!(entry.to_string(), "RSA  [rsaEncryption]");
}
