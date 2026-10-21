use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{Curve, Point, wnaf};
use tc_f2m_custom_v2::named_curves::{SECT233K1, SECT283K1, SECT409K1, SECT571K1};
use tc_f2m_custom_v2::{
    SecT233FieldElement, SecT283FieldElement, SecT409FieldElement, SecT571FieldElement,
    SecTVarCurve,
};

// With cofactor 4, the half-trace test of BC's `SatisfiesOrder` gives what nP = O gives, on
// points in the subgroup and out of it, and the point (0, 1) of order 2 fails it.
fn check<C: Curve<Scalar = PaddedBigUint>>(
    curve: C,
    len: usize,
    decompress: impl Fn(&[u8]) -> Option<C::Point>,
    two_torsion: C::Point,
) {
    let n = curve.order().unwrap().clone();
    let (mut inside, mut outside) = (0, 0);
    for i in 1..=40u8 {
        let mut x = vec![0; len];
        x[len - 1] = i;
        let Some(point) = decompress(&x) else {
            continue;
        };
        let expected = wnaf::wnaf_mul_point::<C>(&point, &n).is_infinity();
        assert_eq!(point.is_valid(), expected, "x = {i}");
        if expected { inside += 1 } else { outside += 1 }
    }
    assert!(
        inside > 0 && outside > 0,
        "{inside} inside, {outside} outside"
    );
    assert!(!two_torsion.is_valid());
}

fn zero_one(len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut one = vec![0; len];
    one[len - 1] = 1;
    (vec![0; len], one)
}

#[test]
fn the_cofactor_4_order_check_agrees_with_multiplying_by_n() {
    let curve = SECT233K1.var_curve();
    let len = curve.field_element_encoding_length();
    let (zero, one) = zero_one(len);
    check::<&SecTVarCurve<SecT233FieldElement>>(
        &curve,
        len,
        |x| curve.decompress_point(0, x),
        curve.create_point(&zero, &one).unwrap(),
    );

    let curve = SECT283K1.var_curve();
    let len = curve.field_element_encoding_length();
    let (zero, one) = zero_one(len);
    check::<&SecTVarCurve<SecT283FieldElement>>(
        &curve,
        len,
        |x| curve.decompress_point(0, x),
        curve.create_point(&zero, &one).unwrap(),
    );

    let curve = SECT409K1.var_curve();
    let len = curve.field_element_encoding_length();
    let (zero, one) = zero_one(len);
    check::<&SecTVarCurve<SecT409FieldElement>>(
        &curve,
        len,
        |x| curve.decompress_point(0, x),
        curve.create_point(&zero, &one).unwrap(),
    );

    let curve = SECT571K1.var_curve();
    let len = curve.field_element_encoding_length();
    let (zero, one) = zero_one(len);
    check::<&SecTVarCurve<SecT571FieldElement>>(
        &curve,
        len,
        |x| curve.decompress_point(0, x),
        curve.create_point(&zero, &one).unwrap(),
    );
}
