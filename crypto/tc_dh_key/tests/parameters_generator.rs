//! `DhParametersGenerator`：安全質數 p = 2q + 1、p ≡ 23 (mod 24)、g = 2、j = 2。

use tc_bigint::BigUint;
use tc_dh_key::{DhError, DhParametersGenerator};
use tc_prime::Primality;

#[test]
fn the_parameters_are_a_safe_prime_with_generator_two() {
    let mut rng = rand::rng();
    let mut generator = DhParametersGenerator::new();
    generator.init(192, 20, &mut rng).unwrap();
    let params = generator.generate_parameters().unwrap();

    let p = BigUint::from(params.p().clone());
    let q = BigUint::from(params.q().unwrap().clone());
    let mut check_rng = rand::rng();
    assert_eq!(p.bits(), 192);
    assert_eq!(&p >> 1, q);
    assert!(p.is_probable_prime(40, &mut check_rng));
    assert!(q.is_probable_prime(40, &mut check_rng));
    assert_eq!(&p % 24u32, BigUint::from(23u8));
    assert_eq!(BigUint::from(params.g().clone()), BigUint::from(2u8));
    assert_eq!(
        params.j().map(|j| BigUint::from(j.clone())),
        Some(BigUint::from(2u8))
    );
    assert_eq!(params.validate(), Ok(()));
}

#[test]
fn init_rejects_a_size_below_64_bits_and_a_zero_certainty() {
    let mut rng = rand::rng();
    assert_eq!(
        DhParametersGenerator::new().init(63, 20, &mut rng),
        Err(DhError::InvalidSize)
    );
    assert_eq!(
        DhParametersGenerator::new().init(64, 0, &mut rng),
        Err(DhError::InvalidCertainty)
    );
}

#[test]
fn generating_before_init_is_an_error() {
    assert_eq!(
        DhParametersGenerator::new().generate_parameters().err(),
        Some(DhError::NotInitialized)
    );
}
