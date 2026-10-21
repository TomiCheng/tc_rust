use tc_bigint::{ArrayEncoding, BigInt, PaddedBigUint};
use tc_ec_core_v2::{Curve, FieldElement, Point, PrimeFieldElement, glv, wnaf};
use tc_fp_curve_v2::named_curves::SECP256K1;
use tc_fp_curve_v2::{FpVarCurve, FpVarPoint};

type Var<'a> = &'a FpVarCurve<'a>;

fn hex(text: &str) -> BigInt {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, text),
    };
    let value = digits.chars().fold(BigInt::from(0u8), |acc, digit| {
        (acc << 4) + BigInt::from(digit.to_digit(16).unwrap())
    });
    if negative { -value } else { value }
}

fn int(text: &str) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    value
}

// BC's `CustomNamedCurves` secp256k1.
const BETA: &str = "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee";

fn split() -> glv::ScalarSplit {
    glv::ScalarSplit::new(
        [
            hex("3086d221a7d46bcde86c90e49284eb15"),
            hex("-e4437ed6010e88286f547fa90abfe4c3"),
        ],
        [
            hex("114ca50f7a8e2f3f657c1108d9d44cfd8"),
            hex("3086d221a7d46bcde86c90e49284eb15"),
        ],
        hex("3086d221a7d46bcde86c90e49284eb153dab"),
        hex("e4437ed6010e88286f547fa90abfe4c42212"),
        272,
    )
}

// φ(x, y) = (βx, y), through the affine coordinates.
fn phi<'a>(point: &FpVarPoint<'a>) -> FpVarPoint<'a> {
    match (point.x(), point.y()) {
        (Some(x), Some(y)) => {
            let beta = x.element_from_big_uint(&int(BETA));
            Var::create_point(&point.curve(), x.multiply(&beta), y)
        }
        _ => point.clone(),
    }
}

// xorshift64 scalars of `bytes` bytes.
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

// φ is multiplication by λ, and the split multiplication gives the wNAF's multiples, the
// order and scalars past it included.
#[test]
fn the_glv_split_multiplies_as_the_wnaf_does_on_secp256k1() {
    let field = SECP256K1.field();
    let curve = SECP256K1.var_curve(&field);
    let g = SECP256K1.var_generator(&curve);
    let lambda = int("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");
    assert!(phi(&g) == wnaf::wnaf_mul_point::<Var<'_>>(&g, &lambda));

    let split = split();
    let n = curve.order().unwrap().clone();
    let mut state = 0x0256_0001;
    let mut scalars: Vec<PaddedBigUint> = [0u8, 1, 2, 3, 255]
        .into_iter()
        .map(PaddedBigUint::from)
        .collect();
    scalars.push(n.clone());
    scalars.extend((0..8).map(|_| scalar(&mut state, 32)));
    scalars.push(scalar(&mut state, 40));
    let three_g = wnaf::wnaf_mul_point::<Var<'_>>(&g, &PaddedBigUint::from(3u8));
    for point in [&g, &three_g] {
        for k in &scalars {
            assert!(
                glv::glv_mul_point::<Var<'_>>(point, k, &split, phi)
                    == wnaf::wnaf_mul_point::<Var<'_>>(point, k)
            );
        }
    }
}

// The named secp256k1 Var curve now multiplies by the split, as BC's custom curve does: the
// multiples are the wNAF's and those of the Ct curve's fixed window.
#[test]
fn the_named_secp256k1_var_curve_multiplies_by_the_split() {
    let field = SECP256K1.field();
    let curve = SECP256K1.var_curve(&field);
    let g = SECP256K1.var_generator(&curve);
    let ct = SECP256K1.ct_curve(&field);
    let h = SECP256K1.ct_generator(&ct);
    let mut state = 0x0256_0002;
    for _ in 0..6 {
        let k = scalar(&mut state, 32);
        let p = Var::multiply(&g, &k);
        assert!(p == wnaf::wnaf_mul_point::<Var<'_>>(&g, &k));
        assert!(p.x() == h.multiply(&k).x());
    }
}

#[test]
fn a_beta_not_below_q_is_refused() {
    let field = SECP256K1.field();
    let q = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    let curve = tc_fp_curve_v2::FpVarCurve::new(
        &field,
        &PaddedBigUint::from(0u8),
        &PaddedBigUint::from(7u8),
        Some(int(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        )),
        Some(PaddedBigUint::from(1u8)),
    )
    .unwrap();
    assert!(curve.with_glv(&q, split()).is_err());
}
