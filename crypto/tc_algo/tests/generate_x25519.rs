#![cfg(feature = "x25519")]

use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_algo::ErrorKind;
use tc_algo::agreement;
use tc_algo::generate::key_pair::KeyPair;
use tc_algo::generate::{self, KeyGenParams};
use tc_algo::params::{AnyPrivateKey, AnyPublicKey};
use tc_asn1::Asn1Oid;
use tc_cfrg_curves::{X25519PrivateKey, X25519PublicKey};

fn x25519_keys(pair: &KeyPair) -> (&X25519PublicKey, &X25519PrivateKey) {
    let (AnyPublicKey::X25519(public), AnyPrivateKey::X25519(private)) =
        (&pair.public, &pair.private)
    else {
        panic!("not an X25519 key pair");
    };
    (public, private)
}

#[test]
fn the_public_key_is_that_of_the_private_key() {
    let pair = generate::key_pair::generate("X25519").unwrap();
    let (public, private) = x25519_keys(&pair);
    assert_eq!(*public, private.generate_public_key());
}

#[test]
fn two_generated_key_pairs_agree_on_a_secret_of_32_bytes() {
    let alice = generate::key_pair::generate("X25519").unwrap();
    let bob = generate::key_pair::generate("X25519").unwrap();
    let alice_secret =
        agreement::calculate("X25519", &alice.private.into(), &bob.public.into()).unwrap();
    let bob_secret =
        agreement::calculate("X25519", &bob.private.into(), &alice.public.into()).unwrap();
    assert_eq!(alice_secret.as_bytes().len(), 32);
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
}

#[test]
fn the_same_seed_gives_the_same_key_pair() {
    let generate = || {
        let mut generator = generate::key_pair::get_by_name("X25519").unwrap();
        generator.with_rng(StdRng::seed_from_u64(7));
        generator.generate().unwrap()
    };
    let (first, second) = (generate(), generate());
    assert_eq!(x25519_keys(&first).0, x25519_keys(&second).0);
    assert_eq!(x25519_keys(&first).1.k(), x25519_keys(&second).1.k());
}

#[test]
fn init_takes_255_bits_and_no_other_size() {
    let mut generator = generate::key_pair::get_by_name("X25519").unwrap();
    generator
        .init(KeyGenParams::Strength { bits: 255 })
        .unwrap();
    for bits in [256, 448] {
        let error = generator
            .init(KeyGenParams::Strength { bits })
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams, "{bits}");
    }
    generator.generate().unwrap();
}

#[test]
fn the_generator_is_found_by_name_case_and_oid() {
    for name in ["X25519", "x25519", "1.3.101.110"] {
        let generator = generate::key_pair::get_by_name(name).unwrap();
        assert_eq!(generator.entry().name(), "X25519", "{name}");
    }
    let oid: Asn1Oid = "1.3.101.110".parse().unwrap();
    let generator = generate::key_pair::get_by_oid(&oid).unwrap();
    assert_eq!(generator.entry().to_string(), "X25519  [id-X25519]");
}
