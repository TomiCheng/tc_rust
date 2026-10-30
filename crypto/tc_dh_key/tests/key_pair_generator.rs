//! `DhKeyPairGenerator`：y = g^x mod p，x 依 BC `CalculatePrivate` 的範圍與長度取得。

mod common;

use common::{group14, n};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{BigUint, PaddedBigUint};
use tc_dh_key::{DhError, DhKeyGenerationParams, DhKeyPairGenerator, DhParameters};
use tc_modular::{ModPow, NonZero};

fn big(value: &PaddedBigUint) -> BigUint {
    BigUint::from(value.clone())
}

#[test]
fn the_public_value_is_g_to_the_private_value() {
    let params = group14();
    let mut rng = rand::rng();
    let mut generator = DhKeyPairGenerator::new();
    generator
        .init(DhKeyGenerationParams::new(params.clone(), &mut rng))
        .unwrap();
    let p = NonZero::new(big(params.p())).unwrap();
    let q = big(params.q().unwrap());
    let mut min = BigUint::from(0u8);
    min.set_bit(159, true);
    for _ in 0..3 {
        let (public_key, private_key) = generator.generate_key_pair().unwrap();
        let x = big(private_key.x());
        assert_eq!(big(public_key.y()), BigUint::from(2u8).mod_pow(&x, &p));
        assert!(x >= min && x <= &q - 2u32, "x in [2^159, q - 2]");
        assert_eq!(public_key.params(), &params);
        assert_eq!(public_key.validate(), Ok(()));
    }
}

#[test]
fn a_set_length_gives_private_values_of_exactly_that_many_bits() {
    let params = group14().with_l(256);
    let mut rng = rand::rng();
    let mut generator = DhKeyPairGenerator::new();
    generator
        .init(DhKeyGenerationParams::new(params, &mut rng))
        .unwrap();
    for _ in 0..3 {
        let (_, private_key) = generator.generate_key_pair().unwrap();
        assert_eq!(big(private_key.x()).bits(), 256);
    }
}

#[test]
fn the_strength_is_l_or_the_bit_length_of_p() {
    let mut rng = rand::rng();
    assert_eq!(
        DhKeyGenerationParams::new(group14(), &mut rng).strength(),
        2048
    );
    assert_eq!(
        DhKeyGenerationParams::new(group14().with_l(256), &mut rng).strength(),
        256
    );
}

#[test]
fn init_rejects_invalid_parameters() {
    let mut rng = rand::rng();
    let mut generator = DhKeyPairGenerator::new();
    let params = DhParameters::new(n(24), n(2));
    assert_eq!(
        generator.init(DhKeyGenerationParams::new(params, &mut rng)),
        Err(DhError::InvalidModulus)
    );
}

#[test]
fn generating_before_init_is_an_error() {
    assert_eq!(
        DhKeyPairGenerator::new().generate_key_pair().err(),
        Some(DhError::NotInitialized)
    );
}
