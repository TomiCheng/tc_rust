use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::Curve;
use tc_ec_core_v2::multiplier::{BaseMultiplier, CombCt, CombVar};
use tc_fp_custom_v2::named_curves::SECP384R1;
use tc_fp_custom_v2::{SecP384R1FieldElement, SecPCtCurve, SecPVarCurve};

type Ct<'a> = &'a SecPCtCurve<SecP384R1FieldElement>;
type Var<'a> = &'a SecPVarCurve<SecP384R1FieldElement>;

// The comb gives the specialized curves' own multiples, for 1, n − 1 and xorshift64 scalars
// below n.
#[test]
fn the_comb_multiplies_as_the_specialized_curves_do() {
    let ct = SECP384R1.ct_curve();
    let g = SECP384R1.ct_generator(&ct);
    let var = SECP384R1.var_curve();
    let h = SECP384R1.var_generator(&var);
    let (comb_ct, comb_var) = (
        CombCt::<Ct<'_>>::new(g.clone()),
        CombVar::<Var<'_>>::new(h.clone()),
    );
    let n = (&ct).order().unwrap().clone();
    let one = PaddedBigUint::from(1u8);
    let mut scalars = vec![one.clone(), &n - &one];
    let mut state = 0xC0B0_0384u64;
    for _ in 0..6 {
        let bytes: Vec<u8> = (0..48)
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
    for k in &scalars {
        assert!(comb_ct.multiply(k) == Ct::multiply(&g, k));
        assert!(comb_var.multiply(k) == Var::multiply(&h, k));
    }
}
