use super::*;
use crate::F2mVarCurve;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve, Point};

fn check<const N: usize>(named: &F2mNamedCurve<N>) {
    let ct_curve = named.ct_curve();
    let var_curve = named.var_curve();
    let lambda = named
        .var_curve()
        .with_coordinate_system(CoordinateSystem::LambdaProjective);
    let g = named.ct_generator(&ct_curve);
    let h = named.var_generator(&var_curve);
    let l = named.var_generator(&lambda);
    let n = ct_curve.order().unwrap();

    assert!(
        g.is_valid() && h.is_valid() && l.is_valid(),
        "m = {}",
        named.m
    );
    assert!(g.multiply(n).is_infinity(), "m = {}", named.m);
    assert!(<&F2mVarCurve as Curve>::multiply(&l, n).is_infinity());
    for k in [2u32, 3, 0xFFFF_FFFF] {
        let k = PaddedBigUint::from(k);
        let expected = <&F2mVarCurve as Curve>::multiply(&h, &k).encode(true);
        assert_eq!(g.multiply(&k).encode(true), expected, "m = {}", named.m);
        assert_eq!(
            <&F2mVarCurve as Curve>::multiply(&l, &k).encode(true),
            expected
        );
    }
    assert!(ct_curve.decode_point(&g.encode(true)).unwrap() == g);
    assert!(var_curve.decode_point(&h.encode(true)).unwrap() == h);
}

#[test]
fn every_sec_2_binary_curve_has_a_valid_generator_of_order_n_on_both_sets() {
    check(&SECT163K1);
    check(&SECT163R1);
    check(&SECT163R2);
    check(&SECT193R1);
    check(&SECT193R2);
    check(&SECT233K1);
    check(&SECT233R1);
    check(&SECT239K1);
    check(&SECT283K1);
    check(&SECT283R1);
    check(&SECT409K1);
    check(&SECT409R1);
    check(&SECT571K1);
    check(&SECT571R1);
}

#[cfg(feature = "small-curves")]
#[test]
fn the_small_curves_have_a_valid_generator_of_order_n_too() {
    check(&SECT113R1);
    check(&SECT113R2);
    check(&SECT131R1);
    check(&SECT131R2);
}
