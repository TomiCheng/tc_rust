use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::Curve;
use tc_ec_core_v2::multiplier::{BaseMultiplier, CombCt, CombVar};
use tc_fp_custom_v2::named_curves::{SECP256K1, SECP384R1};
use tc_fp_custom_v2::{
    SecP256K1FieldElement, SecP384R1FieldElement, SecPCtCurve, SecPCtPrecomputed, SecPVarCurve,
    SecPVarPrecomputed,
};

// 1, n − 1 and xorshift64 scalars below n.
fn scalars(n: &PaddedBigUint, seed: u64) -> Vec<PaddedBigUint> {
    let one = PaddedBigUint::from(1u8);
    let mut scalars = vec![one.clone(), n - &one];
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

// A multiplier built for `g` gives the curve's own multiples of it.
fn agrees<C: Curve<Scalar = PaddedBigUint>, M: BaseMultiplier<C>>(
    g: &C::Point,
    scalars: &[PaddedBigUint],
) {
    let multiplier = M::new(g.clone());
    for k in scalars {
        assert!(multiplier.multiply(k) == C::multiply(g, k));
    }
}

// P-384 takes the wNAF and secp256k1 the GLV split, on the specialized curves.
#[test]
fn every_multiplier_gives_the_specialized_curves_own_multiples() {
    type Ct384<'a> = &'a SecPCtCurve<SecP384R1FieldElement>;
    type Var384<'a> = &'a SecPVarCurve<SecP384R1FieldElement>;
    let (ct, var) = (SECP384R1.ct_curve(), SECP384R1.var_curve());
    let (g, h) = (SECP384R1.ct_generator(&ct), SECP384R1.var_generator(&var));
    let scalars_384 = scalars((&ct).order().unwrap(), 0xC0B0_0384);
    agrees::<Ct384<'_>, CombCt<_>>(&g, &scalars_384);
    agrees::<Ct384<'_>, SecPCtPrecomputed<'_, _>>(&g, &scalars_384);
    agrees::<Var384<'_>, CombVar<_>>(&h, &scalars_384);
    agrees::<Var384<'_>, SecPVarPrecomputed<'_, _>>(&h, &scalars_384);

    type CtK1<'a> = &'a SecPCtCurve<SecP256K1FieldElement>;
    type VarK1<'a> = &'a SecPVarCurve<SecP256K1FieldElement>;
    let (ct, var) = (SECP256K1.ct_curve(), SECP256K1.var_curve());
    let (g, h) = (SECP256K1.ct_generator(&ct), SECP256K1.var_generator(&var));
    let scalars_k1 = scalars((&ct).order().unwrap(), 0xC0B0_0257);
    agrees::<CtK1<'_>, CombCt<_>>(&g, &scalars_k1);
    agrees::<CtK1<'_>, SecPCtPrecomputed<'_, _>>(&g, &scalars_k1);
    agrees::<VarK1<'_>, CombVar<_>>(&h, &scalars_k1);
    agrees::<VarK1<'_>, SecPVarPrecomputed<'_, _>>(&h, &scalars_k1);
}
