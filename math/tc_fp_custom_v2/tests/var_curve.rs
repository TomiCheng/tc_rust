mod common;

use common::*;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve, FieldElement, Point};
use tc_fp_curve_v2::FpVarCurve;
use tc_fp_custom_v2::named_curves::*;
use tc_fp_custom_v2::*;

// Same curve, same scalars: the Jacobian formulas over the specialized fields land on the
// points that the generic curve's do, and the group law holds whatever the projective scale.
fn check<C, D>(g: C::Point, h: D::Point, params: &Params)
where
    C: Curve<Scalar = PaddedBigUint>,
    D: Curve<Scalar = PaddedBigUint>,
{
    let len = g.curve().zero().encoded_length();
    assert_eq!(g.curve().coordinate_system(), CoordinateSystem::Jacobian);
    assert!(g.is_valid());
    assert!(C::multiply(&g, g.curve().order().unwrap()).is_infinity());
    same(&g, &h);
    assert_eq!(
        uncompressed(&C::multiply(&g, &int(params.k))),
        hex(params.kg)
    );

    let mut state = 0x0384_0256_0384_0256;
    for _ in 0..6 {
        let (j, k) = (scalar(&mut state, len), scalar(&mut state, len));
        let (p, q) = (C::multiply(&g, &j), D::multiply(&h, &j));
        let (r, s) = (C::multiply(&g, &k), D::multiply(&h, &k));
        same(&p, &q);
        same(&p.add(&r), &q.add(&s));
        same(&p.add(&r.normalize()), &q.add(&s));
        same(&p.twice(), &q.twice());
        same(&p.twice_plus(&r), &q.twice_plus(&s));
        same(&p.three_times(), &q.three_times());
        same(&p.times_pow2(5), &q.times_pow2(5));
        assert!(p == p.normalize());
        let z = p.projective_z().unwrap();
        assert!(p.normalize_with_inverse(&z.invert().unwrap()) == p);
    }

    let three = PaddedBigUint::from(3u8);
    let two = g.twice();
    assert!(g.add(&g) == two);
    assert!(two.add(&g) == C::multiply(&g, &three));
    assert!(two.add(&g) == two.normalize().add(&g));
    // Equal Z on both sides takes BC's shortcut.
    assert!(two.add(&two) == two.twice());
    assert!(two.add(&two.negate()).is_infinity());
    let o = g.infinity();
    assert!(o.add(&g) == g && g.add(&o) == g && o.twice().is_infinity());
    assert!(o.x().is_none() && o.projective_z().is_none());
}

#[test]
fn secp256r1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP256R1.var_curve();
    let field = field(&P256);
    let generic = generic_var(&field, &P256);
    let h = generic.create_point(&int(P256.gx), &int(P256.gy)).unwrap();
    check::<&SecPVarCurve<SecP256R1FieldElement>, &FpVarCurve<'_>>(
        SECP256R1.var_generator(&curve),
        h,
        &P256,
    );
}

#[test]
fn secp256k1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP256K1.var_curve();
    let field = field(&K256);
    let generic = generic_var(&field, &K256);
    let h = generic.create_point(&int(K256.gx), &int(K256.gy)).unwrap();
    check::<&SecPVarCurve<SecP256K1FieldElement>, &FpVarCurve<'_>>(
        SECP256K1.var_generator(&curve),
        h,
        &K256,
    );
}

#[test]
fn secp384r1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP384R1.var_curve();
    let field = field(&P384);
    let generic = generic_var(&field, &P384);
    let h = generic.create_point(&int(P384.gx), &int(P384.gy)).unwrap();
    check::<&SecPVarCurve<SecP384R1FieldElement>, &FpVarCurve<'_>>(
        SECP384R1.var_generator(&curve),
        h,
        &P384,
    );
}

#[test]
fn the_constant_and_variable_time_curves_agree() {
    let (ct, var) = (SECP256K1.ct_curve(), SECP256K1.var_curve());
    let (g, h) = (SECP256K1.ct_generator(&ct), SECP256K1.var_generator(&var));
    let mut state = 0x5EC9;
    for _ in 0..3 {
        let k = scalar(&mut state, 32);
        same(&g.multiply(&k), &<&SecPVarCurve<_>>::multiply(&h, &k));
    }
    assert!(
        !var.create_point(&hex(K256.gx), &hex(K256.gx))
            .unwrap()
            .is_valid()
    );
}
