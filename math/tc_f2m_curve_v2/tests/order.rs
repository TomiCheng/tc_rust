use tc_ec_core_v2::{Point, wnaf};
use tc_f2m_curve_v2::F2mVarCurve;
use tc_f2m_curve_v2::named_curves::{F2mNamedCurve, SECT233K1, SECT283K1, SECT409K1, SECT571K1};

type Var<'a> = &'a F2mVarCurve;

// With cofactor 4, the half-trace test of BC's `SatisfiesOrder` gives what nP = O gives, on
// points in the subgroup and out of it, and the point (0, 1) of order 2 fails it.
fn check<const N: usize>(named: &F2mNamedCurve<N>) {
    let curve = named.var_curve();
    let n = curve.order().unwrap().clone();
    let len = curve.field_element_encoding_length();
    let (mut inside, mut outside) = (0, 0);
    for i in 1..=40u8 {
        let mut x = vec![0; len];
        x[len - 1] = i;
        let Some(point) = curve.decompress_point(0, &x) else {
            continue;
        };
        let expected = wnaf::wnaf_mul_point::<Var<'_>>(&point, &n).is_infinity();
        assert_eq!(point.is_valid(), expected, "x = {i}");
        if expected { inside += 1 } else { outside += 1 }
    }
    assert!(
        inside > 0 && outside > 0,
        "{inside} inside, {outside} outside"
    );
    assert!(named.var_generator(&curve).is_valid());
    let mut one = vec![0; len];
    one[len - 1] = 1;
    let two_torsion = curve.create_point(&vec![0; len], &one).unwrap();
    assert!(two_torsion.is_on_curve() && !two_torsion.is_valid());
}

#[test]
fn the_cofactor_4_order_check_agrees_with_multiplying_by_n() {
    check(&SECT233K1);
    check(&SECT283K1);
    check(&SECT409K1);
    check(&SECT571K1);
}
