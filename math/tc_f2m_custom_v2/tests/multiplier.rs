use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::multiplier::{BaseMultiplier, CombVar};
use tc_ec_core_v2::{Curve, Point};
use tc_f2m_custom_v2::named_curves::{SECT163K1, SECT163R2};
use tc_f2m_custom_v2::{SecT163FieldElement, SecTVarCurve, SecTVarPrecomputed};

type Var<'a> = &'a SecTVarCurve<SecT163FieldElement>;

// 0, 1, n − 1 and xorshift64 scalars below n.
fn scalars(n: &PaddedBigUint, seed: u64) -> Vec<PaddedBigUint> {
    let one = PaddedBigUint::from(1u8);
    let mut scalars = vec![PaddedBigUint::from(0u8), one.clone(), n - &one];
    let mut state = seed;
    for _ in 0..6 {
        let bytes: Vec<u8> = (0..n.bits().div_ceil(8))
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let Ok(k) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
        scalars.push(k % n);
    }
    scalars
}

// sect163k1 takes the τ-adic NAF and sect163r2 the wNAF, on the specialized curves.
#[test]
fn both_var_multipliers_give_the_specialized_curves_own_multiples() {
    let k163 = SECT163K1.var_curve();
    let g = SECT163K1.var_generator(&k163);
    let r163 = SECT163R2.var_curve();
    let h = SECT163R2.var_generator(&r163);
    for (point, seed) in [(&g, 0xC0B0_1163), (&h, 0xC0B0_2163)] {
        let n = point.curve().order().unwrap().clone();
        let scalars = scalars(&n, seed);
        let comb = CombVar::<Var<'_>>::new(point.clone());
        let precomputed = SecTVarPrecomputed::new(point.clone());
        for k in &scalars {
            let expected = Var::multiply(point, k);
            assert!(comb.multiply(k) == expected);
            assert!(precomputed.multiply(k) == expected);
        }
    }
}
