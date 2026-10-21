use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{Curve, FieldElement, Point, tnaf, wnaf};
use tc_f2m_curve_v2::named_curves::{
    F2mNamedCurve, SECT163K1, SECT163R2, SECT233K1, SECT283K1, SECT409K1, SECT571K1,
};
use tc_f2m_curve_v2::{F2mCtCurve, F2mVarCurve, F2mVarPoint};

type Var<'a> = &'a F2mVarCurve;

// The Frobenius map (x, y) -> (x², y²), through the affine coordinates.
fn tau<'a>(point: &F2mVarPoint<'a>) -> F2mVarPoint<'a> {
    match (point.x(), point.y()) {
        (Some(x), Some(y)) => Var::create_point(&point.curve(), x.square(), y.square()),
        _ => point.clone(),
    }
}

// xorshift64 scalars below 2^bits.
fn scalar(state: &mut u64, bytes: usize) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..bytes)
        .map(|_| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as u8
        })
        .collect();
    let Ok(k) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    k
}

// On the subgroup of order n, the τ-adic window NAF gives the multiples the wNAF does, and
// the Var curve's own multiply, now the τ-adic NAF, those of the Ct curve's ladder.
fn check<const N: usize>(named: &F2mNamedCurve<N>, m: u32) {
    let curve = named.var_curve();
    let g = named.var_generator(&curve);
    assert!(tnaf::is_koblitz(&&curve));
    let n = curve.order().unwrap().clone();
    let table = tnaf::WTauNafTable::new(&g, m, tau);
    let mut state = u64::from(m) * 0x9E37_79B9;
    let mut scalars: Vec<PaddedBigUint> = [0u8, 1, 2, 3, 7]
        .into_iter()
        .map(PaddedBigUint::from)
        .collect();
    scalars.push(n.clone());
    scalars.extend((0..6).map(|_| scalar(&mut state, (m as usize).div_ceil(8) - 1)));
    let ct = named.ct_curve();
    let h = named.ct_generator(&ct);
    for k in &scalars {
        let expected = wnaf::wnaf_mul_point::<Var<'_>>(&g, k);
        let ladder = <&F2mCtCurve>::multiply(&h, k);
        assert_eq!(Var::multiply(&g, k).x(), ladder.x(), "m = {m}");
        assert!(tnaf::wtnaf_mul(&table, k, tau) == expected, "m = {m}");
        assert!(
            tnaf::wtnaf_mul_point::<Var<'_>>(&g, k, m, tau) == expected,
            "m = {m}"
        );
    }
    let five_g = Var::multiply(&g, &PaddedBigUint::from(5u8));
    let k = scalar(&mut state, 16);
    assert!(
        tnaf::wtnaf_mul_point::<Var<'_>>(&five_g, &k, m, tau)
            == wnaf::wnaf_mul_point::<Var<'_>>(&five_g, &k),
        "m = {m}"
    );
}

#[test]
fn the_window_tau_adic_naf_multiplies_as_the_wnaf_does_on_every_koblitz_curve() {
    check(&SECT163K1, 163);
    check(&SECT233K1, 233);
    check(&SECT283K1, 283);
    check(&SECT409K1, 409);
    check(&SECT571K1, 571);
}

#[test]
fn only_koblitz_curves_qualify() {
    let curve = SECT163R2.var_curve();
    assert!(!tnaf::is_koblitz(&&curve));
}
