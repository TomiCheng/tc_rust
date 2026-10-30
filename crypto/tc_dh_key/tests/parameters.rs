//! `DhParameters::validate` 照 BC `DHParameters` 建構子的檢查。

mod common;

use common::{group14, n};
use tc_dh_key::{DhError, DhParameters};

#[test]
fn the_rfc_3526_group_passes_validation() {
    assert_eq!(group14().validate(), Ok(()));
}

#[test]
fn an_even_or_tiny_modulus_is_rejected() {
    for p in [1, 2, 24] {
        assert_eq!(
            DhParameters::new(n(p), n(2)).with_m(0).validate(),
            Err(DhError::InvalidModulus),
            "p = {p}"
        );
    }
}

#[test]
fn the_generator_must_lie_in_two_to_p_minus_two() {
    for g in [0, 1, 22, 23, 30] {
        assert_eq!(
            DhParameters::new(n(23), n(g)).with_m(0).validate(),
            Err(DhError::InvalidGenerator),
            "g = {g}"
        );
    }
    for g in [2, 21] {
        assert_eq!(DhParameters::new(n(23), n(g)).with_m(0).validate(), Ok(()));
    }
}

#[test]
fn a_subgroup_order_as_wide_as_p_is_rejected() {
    let params = DhParameters::new(n(23), n(2)).with_m(0);
    assert_eq!(
        params.clone().with_q(n(17)).validate(),
        Err(DhError::InvalidSubgroupOrder)
    );
    assert_eq!(params.with_q(n(11)).validate(), Ok(()));
}

#[test]
fn the_private_value_lengths_must_fit_below_p() {
    let params = DhParameters::new(n(23), n(2));
    // 沒設 m 時預設 160，大於 23 的 5 個位元。
    assert_eq!(
        params.clone().validate(),
        Err(DhError::InvalidPrivateValueLength)
    );
    assert_eq!(
        params.clone().with_m(5).validate(),
        Err(DhError::InvalidPrivateValueLength)
    );
    assert_eq!(
        params.clone().with_m(2).with_l(5).validate(),
        Err(DhError::InvalidPrivateValueLength)
    );
    assert_eq!(
        params.clone().with_m(3).with_l(2).validate(),
        Err(DhError::InvalidPrivateValueLength)
    );
    assert_eq!(params.with_m(2).with_l(4).validate(), Ok(()));
}

#[test]
fn a_cofactor_below_two_is_rejected() {
    let params = DhParameters::new(n(23), n(2)).with_m(0);
    assert_eq!(
        params.clone().with_j(n(1)).validate(),
        Err(DhError::InvalidCofactor)
    );
    assert_eq!(params.with_j(n(2)).validate(), Ok(()));
}

#[test]
fn the_default_minimum_length_follows_l_as_bc_does() {
    let params = DhParameters::new(n(23), n(2));
    assert_eq!(params.m(), 160);
    assert_eq!(params.clone().with_l(100).m(), 100);
    assert_eq!(params.clone().with_l(300).m(), 160);
    assert_eq!(params.with_l(300).with_m(7).m(), 7);
}

#[test]
fn equality_compares_only_p_g_and_q() {
    let params = DhParameters::new(n(23), n(2)).with_q(n(11));
    assert_eq!(params, params.clone().with_m(3).with_l(4).with_j(n(2)));
    assert_ne!(params, DhParameters::new(n(23), n(2)));
    assert_ne!(params, DhParameters::new(n(23), n(3)).with_q(n(11)));
}
