use core::hint::black_box;
use core::time::Duration;

use criterion::{BenchmarkId, Criterion};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::multiplier::{BaseMultiplier, CombCt, CombVar, PerCall};
use tc_ec_core_v2::{CoordinateSystem, Curve, FieldElement, Point, wnaf};
use tc_fp_curve_v2::{FpCtCurve, FpField, FpVarCurve};
use tc_fp_custom_v2::named_curves::{SECP256K1, SECP256R1, SECP384R1, SECP521R1};
use tc_fp_custom_v2::{
    SecP256K1FieldElement, SecP256R1FieldElement, SecP384R1FieldElement, SecP521R1FieldElement,
    SecPCtCurve, SecPCtPrecomputed, SecPVarCurve, SecPVarPrecomputed,
};

// p, a, b, n, gx and gy of a named curve, for the generic curves.
type Params = [&'static str; 6];

const P256: Params = [
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
];

const P384: Params = [
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
];

const P521: Params = [
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
    "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
    "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
    "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
];

fn int(text: &str) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    value
}

// A scalar of `bytes` bytes below n, the same for both sides.
fn scalar(bytes: usize, n: &str) -> PaddedBigUint {
    let text: String = (0..bytes)
        .map(|i| format!("{:02x}", (i * 37 + 11) % 256))
        .collect();
    let mut text = text;
    text.replace_range(0..2, &n[0..2]);
    text.replace_range(2..4, "00");
    int(&text)
}

fn field<F: FieldElement>(criterion: &mut Criterion, name: &str, x: F, y: F) {
    let mut group = criterion.benchmark_group("p256_multiply");
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| black_box(&x).multiply(black_box(&y)))
    });
    group.finish();

    let mut group = criterion.benchmark_group("p256_square");
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| black_box(&x).square())
    });
    group.finish();

    let mut group = criterion.benchmark_group("p256_invert");
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| black_box(&x).invert())
    });
    group.finish();

    let mut group = criterion.benchmark_group("p256_sqrt");
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| black_box(&x).sqrt())
    });
    group.finish();
}

fn multiply<C: Curve<Scalar = PaddedBigUint>>(
    criterion: &mut Criterion,
    group: &str,
    name: &str,
    g: &C::Point,
    k: &PaddedBigUint,
) {
    let mut group = criterion.benchmark_group(group);
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| C::multiply(black_box(g), black_box(k)))
    });
    group.finish();
}

// The plain wNAF, which the Var curve leaves for the GLV split on the k1 curves.
fn wnaf_multiply<C: Curve>(criterion: &mut Criterion, group: &str, g: &C::Point, k: &C::Scalar) {
    let mut group = criterion.benchmark_group(group);
    group.bench_with_input(BenchmarkId::from_parameter("wnaf"), &(), |b, _| {
        b.iter(|| wnaf::wnaf_mul_point::<C>(black_box(g), black_box(k)))
    });
    group.finish();
}

// A fixed-base multiplier built once, then multiplying; and the cost of building it.
fn base<C: Curve, M: BaseMultiplier<C>>(
    criterion: &mut Criterion,
    group: &str,
    name: &str,
    g: &C::Point,
    k: &C::Scalar,
) {
    let multiplier = M::new(g.clone());
    let mut bench = criterion.benchmark_group(group);
    bench.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| multiplier.multiply(black_box(k)))
    });
    bench.finish();

    let mut bench = criterion.benchmark_group(format!("{group}_build"));
    bench.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| M::new(black_box(g).clone()))
    });
    bench.finish();
}

fn generic_field(params: &Params) -> FpField {
    FpField::new(int(params[0])).unwrap()
}

fn generic_ct<'a>(field: &'a FpField, params: &Params) -> FpCtCurve<'a> {
    let one = Some(PaddedBigUint::from(1u8));
    FpCtCurve::new(
        field,
        &int(params[1]),
        &int(params[2]),
        Some(int(params[3])),
        one,
    )
    .unwrap()
}

fn generic_var<'a>(field: &'a FpField, params: &Params) -> FpVarCurve<'a> {
    let one = Some(PaddedBigUint::from(1u8));
    FpVarCurve::new(
        field,
        &int(params[1]),
        &int(params[2]),
        Some(int(params[3])),
        one,
    )
    .unwrap()
    .with_coordinate_system(CoordinateSystem::Jacobian)
}

fn main() {
    let mut criterion = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15))
        .configure_from_args();
    let c = &mut criterion;

    // P-256: the field, and both multiplications.
    let k = scalar(32, P256[3]);
    let field_256 = generic_field(&P256);
    let generic_ct_256 = generic_ct(&field_256, &P256);
    let generic_g = generic_ct_256
        .create_point(&int(P256[4]), &int(P256[5]))
        .unwrap();
    let custom_ct_256 = SECP256R1.ct_curve();
    let custom_g = SECP256R1.ct_generator(&custom_ct_256);
    field(c, "custom", custom_g.x().unwrap(), custom_g.y().unwrap());
    field(c, "generic", generic_g.x().unwrap(), generic_g.y().unwrap());

    multiply::<&SecPCtCurve<SecP256R1FieldElement>>(c, "p256_ct_multiply", "custom", &custom_g, &k);
    multiply::<&FpCtCurve<'_>>(c, "p256_ct_multiply", "generic", &generic_g, &k);
    let custom_var_256 = SECP256R1.var_curve();
    let generic_var_256 = generic_var(&field_256, &P256);
    multiply::<&SecPVarCurve<SecP256R1FieldElement>>(
        c,
        "p256_var_multiply",
        "custom",
        &SECP256R1.var_generator(&custom_var_256),
        &k,
    );
    multiply::<&FpVarCurve<'_>>(
        c,
        "p256_var_multiply",
        "generic",
        &generic_var_256
            .create_point(&int(P256[4]), &int(P256[5]))
            .unwrap(),
        &k,
    );

    // P-384 and P-521, on Karatsuba products: both multiplications.
    let k = scalar(48, P384[3]);
    let field_384 = generic_field(&P384);
    let (generic_ct_384, generic_var_384) = (
        generic_ct(&field_384, &P384),
        generic_var(&field_384, &P384),
    );
    let (custom_ct_384, custom_var_384) = (SECP384R1.ct_curve(), SECP384R1.var_curve());
    multiply::<&SecPCtCurve<SecP384R1FieldElement>>(
        c,
        "p384_ct_multiply",
        "custom",
        &SECP384R1.ct_generator(&custom_ct_384),
        &k,
    );
    multiply::<&FpCtCurve<'_>>(
        c,
        "p384_ct_multiply",
        "generic",
        &generic_ct_384
            .create_point(&int(P384[4]), &int(P384[5]))
            .unwrap(),
        &k,
    );
    multiply::<&SecPVarCurve<SecP384R1FieldElement>>(
        c,
        "p384_var_multiply",
        "custom",
        &SECP384R1.var_generator(&custom_var_384),
        &k,
    );
    multiply::<&FpVarCurve<'_>>(
        c,
        "p384_var_multiply",
        "generic",
        &generic_var_384
            .create_point(&int(P384[4]), &int(P384[5]))
            .unwrap(),
        &k,
    );

    let k = scalar(66, P521[3]);
    let field_521 = generic_field(&P521);
    let (generic_ct_521, generic_var_521) = (
        generic_ct(&field_521, &P521),
        generic_var(&field_521, &P521),
    );
    let (custom_ct_521, custom_var_521) = (SECP521R1.ct_curve(), SECP521R1.var_curve());
    multiply::<&SecPCtCurve<SecP521R1FieldElement>>(
        c,
        "p521_ct_multiply",
        "custom",
        &SECP521R1.ct_generator(&custom_ct_521),
        &k,
    );
    multiply::<&FpCtCurve<'_>>(
        c,
        "p521_ct_multiply",
        "generic",
        &generic_ct_521
            .create_point(&int(P521[4]), &int(P521[5]))
            .unwrap(),
        &k,
    );
    multiply::<&SecPVarCurve<SecP521R1FieldElement>>(
        c,
        "p521_var_multiply",
        "custom",
        &SECP521R1.var_generator(&custom_var_521),
        &k,
    );
    multiply::<&FpVarCurve<'_>>(
        c,
        "p521_var_multiply",
        "generic",
        &generic_var_521
            .create_point(&int(P521[4]), &int(P521[5]))
            .unwrap(),
        &k,
    );

    // P-256 on the specialized curves: the curve's own table kept, and the comb, against a
    // multiplication per call.
    let k = scalar(32, P256[3]);
    let ct_256 = SECP256R1.ct_curve();
    let g = SECP256R1.ct_generator(&ct_256);
    type Ct256<'a> = &'a SecPCtCurve<SecP256R1FieldElement>;
    base::<Ct256<'_>, PerCall<_>>(c, "p256_ct_base", "per_call", &g, &k);
    base::<Ct256<'_>, SecPCtPrecomputed<'_, _>>(c, "p256_ct_base", "precomputed", &g, &k);
    base::<Ct256<'_>, CombCt<_>>(c, "p256_ct_base", "comb", &g, &k);
    let var_256 = SECP256R1.var_curve();
    let g = SECP256R1.var_generator(&var_256);
    type Var256<'a> = &'a SecPVarCurve<SecP256R1FieldElement>;
    base::<Var256<'_>, PerCall<_>>(c, "p256_var_base", "per_call", &g, &k);
    base::<Var256<'_>, SecPVarPrecomputed<'_, _>>(c, "p256_var_base", "precomputed", &g, &k);
    base::<Var256<'_>, CombVar<_>>(c, "p256_var_base", "comb", &g, &k);

    // secp256k1: the Var curve's GLV split against the plain wNAF.
    let k = scalar(
        32,
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    );
    let var_k256 = SECP256K1.var_curve();
    let g = SECP256K1.var_generator(&var_k256);
    multiply::<&SecPVarCurve<SecP256K1FieldElement>>(c, "k256_var_multiply", "glv", &g, &k);
    wnaf_multiply::<&SecPVarCurve<SecP256K1FieldElement>>(c, "k256_var_multiply", &g, &k);
    type VarK256<'a> = &'a SecPVarCurve<SecP256K1FieldElement>;
    base::<VarK256<'_>, PerCall<_>>(c, "k256_var_base", "per_call", &g, &k);
    base::<VarK256<'_>, SecPVarPrecomputed<'_, _>>(c, "k256_var_base", "precomputed", &g, &k);
    base::<VarK256<'_>, CombVar<_>>(c, "k256_var_base", "comb", &g, &k);

    criterion.final_summary();
}
