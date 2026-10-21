use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::Curve;
use tc_ec_core_v2::multiplier::{BaseMultiplier, CombCt, CombVar};
use tc_fp_curve_v2::named_curves::{FpNamedCurve, SECP256K1, SECP256R1};
use tc_fp_curve_v2::{FpCtCurve, FpVarCurve};

type Ct<'a> = &'a FpCtCurve<'a>;
type Var<'a> = &'a FpVarCurve<'a>;

fn integer(bytes: &[u8]) -> PaddedBigUint {
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(bytes);
    value
}

// 0, 1, 2, n − 1, n and xorshift64 scalars below n.
fn scalars(n: &PaddedBigUint, seed: u64) -> Vec<PaddedBigUint> {
    let one = PaddedBigUint::from(1u8);
    let mut scalars = vec![
        PaddedBigUint::from(0u8),
        one.clone(),
        PaddedBigUint::from(2u8),
        n - &one,
        n.clone(),
    ];
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
        scalars.push(integer(&bytes) % n);
    }
    scalars
}

// The comb gives the curve's own multiples on the Ct and the Var curve.
fn check<const N: usize>(named: &FpNamedCurve<N>, seed: u64) {
    let field = named.field();
    let ct = named.ct_curve(&field);
    let g = named.ct_generator(&ct);
    let comb = CombCt::<Ct<'_>>::new(g.clone());
    let n = ct.order().unwrap().clone();
    for k in scalars(&n, seed) {
        assert!(comb.multiply(&k) == Ct::multiply(&g, &k));
    }

    let var = named.var_curve(&field);
    let h = named.var_generator(&var);
    let comb = CombVar::<Var<'_>>::new(h.clone());
    for k in scalars(&n, seed + 1) {
        assert!(comb.multiply(&k) == Var::multiply(&h, &k));
    }
}

#[test]
fn the_comb_multiplies_as_the_curve_does_with_six_rows() {
    check(&SECP256R1, 0xC0B0_0256);
    check(&SECP256K1, 0xC0B0_0257);
}

#[cfg(feature = "small-curves")]
#[test]
fn the_comb_multiplies_as_the_curve_does_with_five_rows() {
    check(&tc_fp_curve_v2::named_curves::SECP112R1, 0xC0B0_0112);
}

#[test]
#[should_panic(expected = "no wider than the order")]
fn the_ct_comb_refuses_a_scalar_wider_than_the_order() {
    let field = SECP256R1.field();
    let curve = SECP256R1.ct_curve(&field);
    let comb = CombCt::<Ct<'_>>::new(SECP256R1.ct_generator(&curve));
    let mut bytes = [0; 33];
    bytes[0] = 1;
    comb.multiply(&integer(&bytes));
}

#[test]
#[should_panic(expected = "no wider than the order")]
fn the_var_comb_refuses_a_scalar_wider_than_the_order() {
    let field = SECP256R1.field();
    let curve = SECP256R1.var_curve(&field);
    let comb = CombVar::<Var<'_>>::new(SECP256R1.var_generator(&curve));
    let mut bytes = [0; 33];
    bytes[0] = 1;
    comb.multiply(&integer(&bytes));
}
