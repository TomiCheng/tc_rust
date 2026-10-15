use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{Point, PrimeFieldElement};

use super::fp_named_curve::int;
use super::hex::hex;
use super::{FpNamedCurve, SECP256K1, SECP256R1};

fn check(named: &FpNamedCurve<32>, twice_x: &str, twice_y: &str) {
    let field = named.field();
    let ct_curve = named.ct_curve(&field);
    let var_curve = named.var_curve(&field);
    let g = named.ct_generator(&ct_curve);
    let h = named.var_generator(&var_curve);
    let n = ct_curve.order().unwrap();
    let expected: (PaddedBigUint, PaddedBigUint) =
        (int(&hex::<32>(twice_x)), int(&hex::<32>(twice_y)));

    assert!(g.is_valid() && h.is_valid());
    assert!(g.multiply(n).is_infinity() && h.multiply(n).is_infinity());
    let (x, y) = g.twice().affine().unwrap();
    assert_eq!((x.to_big_uint(), y.to_big_uint()), expected);
    assert_eq!(g.twice().encode(true), h.twice().encode(true));
    assert_eq!(ct_curve.decode_point(&g.encode(true)), Ok(g.clone()));
    assert_eq!(var_curve.decode_point(&h.encode(false)), Ok(h.clone()));
}

#[test]
fn secp256k1_generates_its_published_doubling_on_both_curves() {
    check(
        &SECP256K1,
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
    );
}

#[test]
fn secp256r1_generates_its_published_doubling_on_both_curves() {
    check(
        &SECP256R1,
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
    );
}

#[cfg(feature = "small-curves")]
fn agree_in_the_subgroup<const N: usize>(named: &FpNamedCurve<N>) {
    let field = named.field();
    let ct_curve = named.ct_curve(&field);
    let var_curve = named.var_curve(&field);
    let g = named.ct_generator(&ct_curve);
    let h = named.var_generator(&var_curve);
    let n = ct_curve.order().unwrap();

    assert!(g.is_valid() && h.is_valid());
    assert!(g.multiply(n).is_infinity() && h.multiply(n).is_infinity());
    for k in [2u8, 3, 7, 255] {
        let k = PaddedBigUint::from(k);
        assert_eq!(g.multiply(&k).encode(true), h.multiply(&k).encode(true));
    }
    assert_eq!(ct_curve.decode_point(&g.encode(true)), Ok(g.clone()));
}

#[cfg(feature = "small-curves")]
#[test]
fn the_small_curves_agree_on_both_sets_within_the_subgroup_of_g() {
    agree_in_the_subgroup(&super::SECP112R1);
    agree_in_the_subgroup(&super::SECP112R2);
    agree_in_the_subgroup(&super::SECP128R2);
}
