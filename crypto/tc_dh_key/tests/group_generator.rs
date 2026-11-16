//! `DhGroupGenerator`：安全質數 p = 2q + 1、p ≡ 23 (mod 24)、g = 2、j = 2。

use tc_bigint::BigUint;
use tc_dh_key::{DhError, DhGroupGenerationParams, DhGroupGenerator};
use tc_prime::Primality;

#[test]
fn the_group_is_a_safe_prime_with_generator_two() {
    let mut generator = DhGroupGenerator::new(rand::rng());
    generator
        .init(
            &DhGroupGenerationParams::new()
                .with_size(192)
                .with_certainty(20),
        )
        .unwrap();
    let group = generator.generate_group().unwrap();

    let p = BigUint::from(group.p().clone());
    let q = BigUint::from(group.q().unwrap().clone());
    let mut check_rng = rand::rng();
    assert_eq!(p.bits(), 192);
    assert_eq!(&p >> 1, q);
    assert!(p.is_probable_prime(40, &mut check_rng));
    assert!(q.is_probable_prime(40, &mut check_rng));
    assert_eq!(&p % 24u32, BigUint::from(23u8));
    assert_eq!(BigUint::from(group.g().clone()), BigUint::from(2u8));
    assert_eq!(
        group.j().map(|j| BigUint::from(j.clone())),
        Some(BigUint::from(2u8))
    );
    assert_eq!(group.validate(), Ok(()));
}

#[test]
fn init_rejects_a_size_below_64_bits_and_a_zero_certainty() {
    let mut generator = DhGroupGenerator::new(rand::rng());
    let params = DhGroupGenerationParams::new();
    assert_eq!(
        generator.init(&params.with_size(63)),
        Err(DhError::InvalidSize)
    );
    assert_eq!(
        generator.init(&params.with_size(64).with_certainty(0)),
        Err(DhError::InvalidCertainty)
    );
}

#[test]
fn the_defaults_are_2048_bits_and_certainty_100() {
    let params = DhGroupGenerationParams::new();
    assert_eq!((params.size(), params.certainty()), (2048, 100));
    assert_eq!(DhGroupGenerationParams::default(), params);
}

#[test]
fn generating_before_init_is_an_error() {
    assert_eq!(
        DhGroupGenerator::new(rand::rng()).generate_group().err(),
        Some(DhError::NotInitialized)
    );
}
