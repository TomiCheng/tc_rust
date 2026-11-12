#![cfg(feature = "x448")]

use std::sync::LazyLock;

use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_algo_old::{Algo, AnyPrivateKey, AnyPublicKey, ErrorKind, KeyGenParams, KeyPair};
use tc_asn1::Asn1Oid;
use tc_cfrg_curves::{X448PrivateKey, X448PublicKey};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

fn x448_keys(pair: &KeyPair) -> (&X448PublicKey, &X448PrivateKey) {
    let (AnyPublicKey::X448(public), AnyPrivateKey::X448(private)) = (&pair.public, &pair.private)
    else {
        panic!("not an X448 key pair");
    };
    (public, private)
}

#[test]
fn the_public_key_is_that_of_the_private_key() {
    let pair = ALGO.key_pair_generator().generate("X448").unwrap();
    let (public, private) = x448_keys(&pair);
    assert_eq!(*public, private.generate_public_key());
}

#[test]
fn two_generated_key_pairs_agree_on_a_secret_of_56_bytes() {
    let alice = ALGO.key_pair_generator().generate("X448").unwrap();
    let bob = ALGO.key_pair_generator().generate("X448").unwrap();
    let alice_secret = ALGO
        .agreement()
        .calculate("X448", &alice.private.into(), &bob.public.into())
        .unwrap();
    let bob_secret = ALGO
        .agreement()
        .calculate("X448", &bob.private.into(), &alice.public.into())
        .unwrap();
    assert_eq!(alice_secret.as_bytes().len(), 56);
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
}

#[test]
fn the_same_seed_gives_the_same_key_pair() {
    let generate = || {
        let mut generator = ALGO.key_pair_generator().get_by_name("X448").unwrap();
        generator.with_rng(StdRng::seed_from_u64(7));
        generator.generate().unwrap()
    };
    let (first, second) = (generate(), generate());
    assert_eq!(x448_keys(&first).0, x448_keys(&second).0);
    assert_eq!(x448_keys(&first).1.k(), x448_keys(&second).1.k());
}

#[test]
fn init_takes_448_bits_and_no_other_size() {
    let mut generator = ALGO.key_pair_generator().get_by_name("X448").unwrap();
    generator
        .init(KeyGenParams::Strength { bits: 448 })
        .unwrap();
    for bits in [255, 456] {
        let error = generator.init(KeyGenParams::Strength { bits }).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams, "{bits}");
    }
    generator.generate().unwrap();
}

#[test]
fn the_generator_is_found_by_name_case_and_oid() {
    for name in ["X448", "x448", "1.3.101.111"] {
        let generator = ALGO.key_pair_generator().get_by_name(name).unwrap();
        assert_eq!(generator.entry().name(), "X448", "{name}");
    }
    let oid: Asn1Oid = "1.3.101.111".parse().unwrap();
    let generator = ALGO.key_pair_generator().get_by_oid(&oid).unwrap();
    assert_eq!(generator.entry().to_string(), "X448  [id-X448]");
}
