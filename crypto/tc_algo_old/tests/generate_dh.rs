#![cfg(feature = "dh")]

use std::sync::LazyLock;

use std::error::Error;
use tc_algo_old::{
    Algo, AnyPrivateKey, AnyPublicKey, ErrorKind, KeyGenParams, KeyPair, KeyPairGenerator,
};

use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_bigint::PaddedBigUint;
use tc_dh_key::standard_groups::{rfc3526_2048, rfc7919_ffdhe2048};
use tc_dh_key::{DhParameters, DhPrivateKey, DhPublicKey};

// One instance for the whole file, so that its tables are built once
#[allow(
    dead_code,
    reason = "unused when the features of the tests here are off"
)]
static ALGO: LazyLock<Algo> = LazyLock::new(Algo::new);

fn dh_keys(pair: &KeyPair) -> (&DhPublicKey, &DhPrivateKey) {
    let (AnyPublicKey::Dh(public), AnyPrivateKey::Dh(private)) = (&pair.public, &pair.private)
    else {
        panic!("not a DH key pair");
    };
    (public, private)
}

fn generator(group: DhParameters) -> KeyPairGenerator {
    let mut generator = ALGO.key_pair_generator().get_by_name("DH").unwrap();
    generator.init(group).unwrap();
    generator
}

#[test]
fn a_dh_key_pair_is_in_the_group_asked_for() {
    let pair = generator(rfc3526_2048()).generate().unwrap();
    let (public, private) = dh_keys(&pair);
    assert_eq!(*public.params(), rfc3526_2048());
    assert_eq!(*private.params(), rfc3526_2048());
    public.validate().unwrap();
}

#[test]
fn two_generated_key_pairs_agree_on_one_secret() {
    let mut generator = generator(rfc7919_ffdhe2048());
    let alice = generator.generate().unwrap();
    let bob = generator.generate().unwrap();
    let alice_secret = ALGO
        .agreement()
        .calculate("DH", &alice.private.into(), &bob.public.into())
        .unwrap();
    let bob_secret = ALGO
        .agreement()
        .calculate("DH", &bob.private.into(), &alice.public.into())
        .unwrap();
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
}

#[test]
fn the_same_seed_gives_the_same_key_pair() {
    let generate = || {
        let mut generator = generator(rfc3526_2048());
        generator.with_rng(StdRng::seed_from_u64(7));
        generator.generate().unwrap()
    };
    let (first, second) = (generate(), generate());
    assert_eq!(dh_keys(&first).0.y(), dh_keys(&second).0.y());
    assert_eq!(dh_keys(&first).1.x(), dh_keys(&second).1.x());
}

#[test]
fn without_init_there_is_no_group_to_generate_in() {
    let mut generator = ALGO.key_pair_generator().get_by_name("DH").unwrap();
    let error = generator.generate().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
    let error = ALGO.key_pair_generator().generate("DH").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
}

#[test]
fn a_size_alone_names_no_group_and_is_refused() {
    let mut generator = ALGO.key_pair_generator().get_by_name("DH").unwrap();
    let error = generator
        .init(KeyGenParams::Strength { bits: 2048 })
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
}

#[test]
fn a_bad_group_is_reported_with_the_dh_error_underneath() {
    let even = DhParameters::new(PaddedBigUint::from(24u8), PaddedBigUint::from(5u8));
    let error = generator(even).generate().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidKeyGenParams);
    assert!(error.source().is_some());
}

#[test]
fn the_generator_is_found_by_name_alias_and_case() {
    for name in ["DH", "dh", "DIFFIEHELLMAN", "DiffieHellman"] {
        let generator = ALGO.key_pair_generator().get_by_name(name).unwrap();
        assert_eq!(generator.entry().name(), "DH", "{name}");
    }
}

#[test]
fn the_entry_shows_its_name_and_has_no_oid() {
    let entry = ALGO
        .key_pair_generator()
        .algorithms()
        .find(|entry| entry.name() == "DH")
        .unwrap();
    assert!(entry.oids().is_empty());
    assert_eq!(entry.to_string(), "DH");
}
