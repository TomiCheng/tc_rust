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

#[cfg(feature = "small-curves")]
#[test]
fn secp128r1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP128R1.var_curve();
    let field = field(&R128);
    let generic = generic_var(&field, &R128);
    let h = generic.create_point(&int(R128.gx), &int(R128.gy)).unwrap();
    check::<&SecPVarCurve<SecP128R1FieldElement>, &FpVarCurve<'_>>(
        SECP128R1.var_generator(&curve),
        h,
        &R128,
    );
}

#[cfg(feature = "small-curves")]
#[test]
fn secp160k1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP160K1.var_curve();
    let field = field(&K160);
    let generic = generic_var(&field, &K160);
    let h = generic.create_point(&int(K160.gx), &int(K160.gy)).unwrap();
    check::<&SecPVarCurve<SecP160R2FieldElement>, &FpVarCurve<'_>>(
        SECP160K1.var_generator(&curve),
        h,
        &K160,
    );
}

#[cfg(feature = "small-curves")]
#[test]
fn secp160r1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP160R1.var_curve();
    let field = field(&R160);
    let generic = generic_var(&field, &R160);
    let h = generic.create_point(&int(R160.gx), &int(R160.gy)).unwrap();
    check::<&SecPVarCurve<SecP160R1FieldElement>, &FpVarCurve<'_>>(
        SECP160R1.var_generator(&curve),
        h,
        &R160,
    );
}

#[cfg(feature = "small-curves")]
#[test]
fn secp160r2_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP160R2.var_curve();
    let field = field(&R160_2);
    let generic = generic_var(&field, &R160_2);
    let h = generic
        .create_point(&int(R160_2.gx), &int(R160_2.gy))
        .unwrap();
    check::<&SecPVarCurve<SecP160R2FieldElement>, &FpVarCurve<'_>>(
        SECP160R2.var_generator(&curve),
        h,
        &R160_2,
    );
}

#[test]
fn secp192k1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP192K1.var_curve();
    let field = field(&K192);
    let generic = generic_var(&field, &K192);
    let h = generic.create_point(&int(K192.gx), &int(K192.gy)).unwrap();
    check::<&SecPVarCurve<SecP192K1FieldElement>, &FpVarCurve<'_>>(
        SECP192K1.var_generator(&curve),
        h,
        &K192,
    );
}

#[test]
fn secp192r1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP192R1.var_curve();
    let field = field(&P192);
    let generic = generic_var(&field, &P192);
    let h = generic.create_point(&int(P192.gx), &int(P192.gy)).unwrap();
    check::<&SecPVarCurve<SecP192R1FieldElement>, &FpVarCurve<'_>>(
        SECP192R1.var_generator(&curve),
        h,
        &P192,
    );
}

#[test]
fn secp224k1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP224K1.var_curve();
    let field = field(&K224);
    let generic = generic_var(&field, &K224);
    let h = generic.create_point(&int(K224.gx), &int(K224.gy)).unwrap();
    check::<&SecPVarCurve<SecP224K1FieldElement>, &FpVarCurve<'_>>(
        SECP224K1.var_generator(&curve),
        h,
        &K224,
    );
}

#[test]
fn secp224r1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP224R1.var_curve();
    let field = field(&P224);
    let generic = generic_var(&field, &P224);
    let h = generic.create_point(&int(P224.gx), &int(P224.gy)).unwrap();
    check::<&SecPVarCurve<SecP224R1FieldElement>, &FpVarCurve<'_>>(
        SECP224R1.var_generator(&curve),
        h,
        &P224,
    );
}

#[test]
fn secp521r1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SECP521R1.var_curve();
    let field = field(&P521);
    let generic = generic_var(&field, &P521);
    let h = generic.create_point(&int(P521.gx), &int(P521.gy)).unwrap();
    check::<&SecPVarCurve<SecP521R1FieldElement>, &FpVarCurve<'_>>(
        SECP521R1.var_generator(&curve),
        h,
        &P521,
    );
}

#[test]
fn sm2p256v1_adds_and_doubles_as_the_generic_curve_does() {
    let curve = SM2P256V1.var_curve();
    let field = field(&SM2);
    let generic = generic_var(&field, &SM2);
    let h = generic.create_point(&int(SM2.gx), &int(SM2.gy)).unwrap();
    check::<&SecPVarCurve<SM2P256V1FieldElement>, &FpVarCurve<'_>>(
        SM2P256V1.var_generator(&curve),
        h,
        &SM2,
    );
}
