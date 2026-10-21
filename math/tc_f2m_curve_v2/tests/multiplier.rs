use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::Curve;
use tc_ec_core_v2::multiplier::{BaseMultiplier, CombVar};
use tc_f2m_curve_v2::named_curves::{F2mNamedCurve, SECT163R2, SECT283K1};
use tc_f2m_curve_v2::{F2mVarCurve, F2mVarPrecomputed};

type Var<'a> = &'a F2mVarCurve;

// Both Var multipliers give the curve's own multiples of G, for 0, 1, n − 1, n and xorshift64
// scalars below n.
fn check<const N: usize>(named: &F2mNamedCurve<N>, seed: u64) {
    let curve = named.var_curve();
    let g = named.var_generator(&curve);
    let n = curve.order().unwrap().clone();
    let one = PaddedBigUint::from(1u8);
    let mut scalars = vec![PaddedBigUint::from(0u8), one.clone(), &n - &one, n.clone()];
    let mut state = seed;
    for _ in 0..8 {
        let bytes: Vec<u8> = (0..n.bits().div_ceil(8))
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let Ok(k) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
        scalars.push(k % &n);
    }
    let comb = CombVar::<Var<'_>>::new(g.clone());
    let precomputed = F2mVarPrecomputed::new(g.clone());
    for k in &scalars {
        let expected = Var::multiply(&g, k);
        assert!(comb.multiply(k) == expected);
        assert!(precomputed.multiply(k) == expected);
    }
}

// sect163r2 takes the wNAF and sect283k1 the τ-adic NAF.
#[test]
fn every_var_multiplier_gives_the_curves_own_multiples() {
    check(&SECT163R2, 0xC0B0_0163);
    check(&SECT283K1, 0xC0B0_0283);
}
