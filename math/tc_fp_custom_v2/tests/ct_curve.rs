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
