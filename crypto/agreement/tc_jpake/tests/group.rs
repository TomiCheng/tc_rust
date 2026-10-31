//! `JPakePrimeOrderGroup::validate`：Bouncy Castle `JPakePrimeOrderGroupTest` 的情境，以及
//! 標準群組通過完整的檢查。

use tc_bigint::PaddedBigUint;
use tc_jpake::standard_groups::{nist_2048, nist_3072, sun_jce_1024};
use tc_jpake::{JPakeError, JPakePrimeOrderGroup};

fn group(p: u8, q: u8, g: u8) -> JPakePrimeOrderGroup {
    JPakePrimeOrderGroup::new(
        PaddedBigUint::from(p),
        PaddedBigUint::from(q),
        PaddedBigUint::from(g),
    )
}

#[test]
fn each_condition_of_a_group_is_checked() {
    let mut rng = rand::rng();
    for ((p, q, g), error) in [
        ((7, 5, 6), JPakeError::OrderNotDividing),
        ((11, 5, 1), JPakeError::GeneratorOutOfRange),
        ((11, 5, 11), JPakeError::GeneratorOutOfRange),
        ((11, 5, 6), JPakeError::GeneratorOrderMismatch),
        ((15, 2, 4), JPakeError::ModulusNotPrime),
        ((7, 6, 3), JPakeError::OrderNotPrime),
        ((7, 2, 6), JPakeError::OrderNotPrime),
        ((7, 0, 3), JPakeError::OrderNotPrime),
        ((0, 3, 2), JPakeError::ModulusNotPrime),
    ] {
        assert_eq!(
            group(p, q, g).validate(&mut rng),
            Err(error),
            "p = {p}, q = {q}, g = {g}"
        );
    }
    assert_eq!(group(7, 3, 4).validate(&mut rng), Ok(()));
}

#[test]
fn the_standard_groups_pass_the_checks_they_skip() {
    let mut rng = rand::rng();
    for standard in [sun_jce_1024(), nist_2048(), nist_3072()] {
        let group = JPakePrimeOrderGroup::new(
            standard.p().clone(),
            standard.q().clone(),
            standard.g().clone(),
        );
        assert_eq!(group.validate(&mut rng), Ok(()));
        assert_eq!(standard.validate(&mut rng), Ok(()));
    }
}
