mod common;

use common::*;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{Curve, FieldElement, Point};
use tc_fp_curve_v2::FpCtCurve;
use tc_fp_custom_v2::named_curves::*;
use tc_fp_custom_v2::*;

// Same curve, same scalars: the specialized fields under the complete formulas land on the
// points that the generic curve's Montgomery field does, and on k·G computed apart.
fn check<C, D>(g: C::Point, h: D::Point, params: &Params)
where
    C: Curve<Scalar = PaddedBigUint>,
    D: Curve<Scalar = PaddedBigUint>,
{
    let len = g.curve().zero().encoded_length();
    assert!(g.is_valid());
    assert!(C::multiply(&g, g.curve().order().unwrap()).is_infinity());
    same(&g, &h);
    assert_eq!(
        uncompressed(&C::multiply(&g, &int(params.k))),
        hex(params.kg)
    );

    let mut state = 0x0256_0384_0256_0384;
    for _ in 0..3 {
        let (j, k) = (scalar(&mut state, len), scalar(&mut state, len));
        let (p, q) = (C::multiply(&g, &j), D::multiply(&h, &j));
        let (r, s) = (C::multiply(&g, &k), D::multiply(&h, &k));
        same(&p, &q);
        same(&p.add(&r), &q.add(&s));
        same(&p.twice(), &q.twice());
        same(&p.add(&r.negate()), &q.add(&s.negate()));
    }

    let o = g.infinity();
    assert!(g.add(&g.negate()).is_infinity());
    assert!(o.add(&g) == g && g.add(&o) == g);
    assert!(o.add(&o).is_infinity() && o.twice().is_infinity());
    assert!(g.add(&g) == g.twice());
    assert!(g.twice().add(&g) == C::multiply(&g, &PaddedBigUint::from(3u8)));
    assert!(g.twice().normalize() == g.twice());
}

#[test]
fn secp256r1_multiplies_as_the_generic_curve_does() {
    let curve = SECP256R1.ct_curve();
    let field = field(&P256);
    let generic = generic_ct(&field, &P256);
    let h = generic.create_point(&int(P256.gx), &int(P256.gy)).unwrap();
    check::<&SecPCtCurve<SecP256R1FieldElement>, &FpCtCurve<'_>>(
        SECP256R1.ct_generator(&curve),
        h,
        &P256,
    );
}

#[test]
fn secp256k1_multiplies_as_the_generic_curve_does() {
    let curve = SECP256K1.ct_curve();
    let field = field(&K256);
    let generic = generic_ct(&field, &K256);
    let h = generic.create_point(&int(K256.gx), &int(K256.gy)).unwrap();
    check::<&SecPCtCurve<SecP256K1FieldElement>, &FpCtCurve<'_>>(
        SECP256K1.ct_generator(&curve),
        h,
        &K256,
    );
}

#[test]
fn secp384r1_multiplies_as_the_generic_curve_does() {
    let curve = SECP384R1.ct_curve();
    let field = field(&P384);
    let generic = generic_ct(&field, &P384);
    let h = generic.create_point(&int(P384.gx), &int(P384.gy)).unwrap();
    check::<&SecPCtCurve<SecP384R1FieldElement>, &FpCtCurve<'_>>(
        SECP384R1.ct_generator(&curve),
        h,
        &P384,
    );
}

#[test]
fn a_point_off_the_curve_is_not_valid() {
    let curve = SECP256R1.ct_curve();
    let g = SECP256R1.ct_generator(&curve);
    let mut gy = hex(P256.gy);
    gy[31] ^= 1;
    let off = curve.create_point(&hex(P256.gx), &gy).unwrap();
    assert!(!off.is_on_curve() && !off.is_valid());
    assert!(g.is_on_curve() && g.affine().is_some());
    assert!(curve.infinity().affine().is_none());
}

#[cfg(feature = "small-curves")]
#[test]
fn secp128r1_multiplies_as_the_generic_curve_does() {
    let curve = SECP128R1.ct_curve();
    let field = field(&R128);
    let generic = generic_ct(&field, &R128);
    let h = generic.create_point(&int(R128.gx), &int(R128.gy)).unwrap();
    check::<&SecPCtCurve<SecP128R1FieldElement>, &FpCtCurve<'_>>(
        SECP128R1.ct_generator(&curve),
        h,
        &R128,
    );
}

#[cfg(feature = "small-curves")]
#[test]
fn secp160k1_multiplies_as_the_generic_curve_does() {
    let curve = SECP160K1.ct_curve();
    let field = field(&K160);
    let generic = generic_ct(&field, &K160);
    let h = generic.create_point(&int(K160.gx), &int(K160.gy)).unwrap();
    check::<&SecPCtCurve<SecP160R2FieldElement>, &FpCtCurve<'_>>(
        SECP160K1.ct_generator(&curve),
        h,
        &K160,
    );
}

#[cfg(feature = "small-curves")]
#[test]
fn secp160r1_multiplies_as_the_generic_curve_does() {
    let curve = SECP160R1.ct_curve();
    let field = field(&R160);
    let generic = generic_ct(&field, &R160);
    let h = generic.create_point(&int(R160.gx), &int(R160.gy)).unwrap();
    check::<&SecPCtCurve<SecP160R1FieldElement>, &FpCtCurve<'_>>(
        SECP160R1.ct_generator(&curve),
        h,
        &R160,
    );
}

#[cfg(feature = "small-curves")]
#[test]
fn secp160r2_multiplies_as_the_generic_curve_does() {
    let curve = SECP160R2.ct_curve();
    let field = field(&R160_2);
    let generic = generic_ct(&field, &R160_2);
    let h = generic
        .create_point(&int(R160_2.gx), &int(R160_2.gy))
        .unwrap();
    check::<&SecPCtCurve<SecP160R2FieldElement>, &FpCtCurve<'_>>(
        SECP160R2.ct_generator(&curve),
        h,
        &R160_2,
    );
}

#[test]
fn secp192k1_multiplies_as_the_generic_curve_does() {
    let curve = SECP192K1.ct_curve();
    let field = field(&K192);
    let generic = generic_ct(&field, &K192);
    let h = generic.create_point(&int(K192.gx), &int(K192.gy)).unwrap();
    check::<&SecPCtCurve<SecP192K1FieldElement>, &FpCtCurve<'_>>(
        SECP192K1.ct_generator(&curve),
        h,
        &K192,
    );
}

#[test]
fn secp192r1_multiplies_as_the_generic_curve_does() {
    let curve = SECP192R1.ct_curve();
    let field = field(&P192);
    let generic = generic_ct(&field, &P192);
    let h = generic.create_point(&int(P192.gx), &int(P192.gy)).unwrap();
    check::<&SecPCtCurve<SecP192R1FieldElement>, &FpCtCurve<'_>>(
        SECP192R1.ct_generator(&curve),
        h,
        &P192,
    );
}

#[test]
fn secp224k1_multiplies_as_the_generic_curve_does() {
    let curve = SECP224K1.ct_curve();
    let field = field(&K224);
    let generic = generic_ct(&field, &K224);
    let h = generic.create_point(&int(K224.gx), &int(K224.gy)).unwrap();
    check::<&SecPCtCurve<SecP224K1FieldElement>, &FpCtCurve<'_>>(
        SECP224K1.ct_generator(&curve),
        h,
        &K224,
    );
}

#[test]
fn secp224r1_multiplies_as_the_generic_curve_does() {
    let curve = SECP224R1.ct_curve();
    let field = field(&P224);
    let generic = generic_ct(&field, &P224);
    let h = generic.create_point(&int(P224.gx), &int(P224.gy)).unwrap();
    check::<&SecPCtCurve<SecP224R1FieldElement>, &FpCtCurve<'_>>(
        SECP224R1.ct_generator(&curve),
        h,
        &P224,
    );
}

#[test]
fn secp521r1_multiplies_as_the_generic_curve_does() {
    let curve = SECP521R1.ct_curve();
    let field = field(&P521);
    let generic = generic_ct(&field, &P521);
    let h = generic.create_point(&int(P521.gx), &int(P521.gy)).unwrap();
    check::<&SecPCtCurve<SecP521R1FieldElement>, &FpCtCurve<'_>>(
        SECP521R1.ct_generator(&curve),
        h,
        &P521,
    );
}

#[test]
fn sm2p256v1_multiplies_as_the_generic_curve_does() {
    let curve = SM2P256V1.ct_curve();
    let field = field(&SM2);
    let generic = generic_ct(&field, &SM2);
    let h = generic.create_point(&int(SM2.gx), &int(SM2.gy)).unwrap();
    check::<&SecPCtCurve<SM2P256V1FieldElement>, &FpCtCurve<'_>>(
        SM2P256V1.ct_generator(&curve),
        h,
        &SM2,
    );
}
