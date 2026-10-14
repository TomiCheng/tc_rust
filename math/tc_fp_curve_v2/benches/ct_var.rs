use core::hint::black_box;
use core::time::Duration;

use criterion::{BenchmarkId, Criterion};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::wnaf::sum_of_two_multiplies;
use tc_ec_core_v2::{CoordinateSystem, Curve, FieldElement, Point};
use tc_fp_curve_v2::FpVarCurve;
use tc_fp_curve_v2::named_curves::SECP256R1;

const SYSTEMS: [CoordinateSystem; 4] = [
    CoordinateSystem::Affine,
    CoordinateSystem::Homogeneous,
    CoordinateSystem::Jacobian,
    CoordinateSystem::JacobianModified,
];

fn hex(text: &str) -> PaddedBigUint {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes).unwrap()
}

fn k() -> PaddedBigUint {
    hex("c51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd")
}

fn u1() -> PaddedBigUint {
    hex("4a89c2ff1b3e0d7a6c5e8f9031d2b4a7e6c9f8b2d1e0a3c4b5f6e7d8c9a0b1c2")
}

fn u2() -> PaddedBigUint {
    hex("9e3779b97f4a7c15f39cc0605cedc8341082276bf3a27251f86c6a11d0c18e95")
}

fn field_operations(criterion: &mut Criterion) {
    let field = SECP256R1.field();
    let curve = SECP256R1.var_curve(&field);
    let g = SECP256R1.var_generator(&curve);
    let x = g.x().unwrap();
    let y = g.y().unwrap();

    let mut group = criterion.benchmark_group("field");
    group.bench_function("multiply", |b| {
        b.iter(|| black_box(&x).multiply(black_box(&y)))
    });
    group.bench_function("square", |b| b.iter(|| black_box(&x).square()));
    group.bench_function("invert", |b| b.iter(|| black_box(&x).invert()));
    group.finish();
}

fn scalar_multiplication(criterion: &mut Criterion) {
    let field = SECP256R1.field();
    let k = k();
    let mut group = criterion.benchmark_group("k*G");

    let ct_curve = SECP256R1.ct_curve(&field);
    let ct_g = SECP256R1.ct_generator(&ct_curve);
    group.bench_function("ct fixed window", |b| {
        b.iter(|| black_box(&ct_g).multiply(black_box(&k)))
    });

    for system in SYSTEMS {
        let curve = SECP256R1.var_curve(&field).with_coordinate_system(system);
        let g = SECP256R1.var_generator(&curve);
        group.bench_with_input(
            BenchmarkId::new("var wnaf", format!("{system:?}")),
            &g,
            |b, g| b.iter(|| <&FpVarCurve<'_> as Curve>::multiply(black_box(g), black_box(&k))),
        );
        group.bench_with_input(
            BenchmarkId::new("var double-and-add", format!("{system:?}")),
            &g,
            |b, g| b.iter(|| black_box(g).multiply(black_box(&k))),
        );
    }
    group.finish();
}

fn verification(criterion: &mut Criterion) {
    let field = SECP256R1.field();
    let (u1, u2) = (u1(), u2());
    let mut group = criterion.benchmark_group("u1*G + u2*Q");

    let ct_curve = SECP256R1.ct_curve(&field);
    let ct_g = SECP256R1.ct_generator(&ct_curve);
    let ct_q = ct_g.multiply(&k());
    group.bench_function("ct two multiplications", |b| {
        b.iter(|| {
            black_box(&ct_g)
                .multiply(black_box(&u1))
                .add(&black_box(&ct_q).multiply(black_box(&u2)))
        })
    });

    for system in [
        CoordinateSystem::Jacobian,
        CoordinateSystem::JacobianModified,
    ] {
        let curve = SECP256R1.var_curve(&field).with_coordinate_system(system);
        let g = SECP256R1.var_generator(&curve);
        let q = g.multiply(&k());
        group.bench_function(
            BenchmarkId::new("var interleaved wnaf", format!("{system:?}")),
            |b| {
                b.iter(|| {
                    sum_of_two_multiplies::<&FpVarCurve<'_>>(
                        black_box(&g),
                        black_box(&u1),
                        black_box(&q),
                        black_box(&u2),
                    )
                })
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15))
        .configure_from_args();
    field_operations(&mut criterion);
    scalar_multiplication(&mut criterion);
    verification(&mut criterion);
    criterion.final_summary();
}
