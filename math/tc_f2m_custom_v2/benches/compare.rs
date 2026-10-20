use core::hint::black_box;
use core::time::Duration;

use criterion::{BenchmarkId, Criterion};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_ec_core_v2::{CoordinateSystem, Curve, FieldElement, Point};
use tc_f2m_curve_v2::named_curves as generic;
use tc_f2m_curve_v2::{F2mCtCurve, F2mVarCurve};
use tc_f2m_custom_v2::named_curves::SECT163R2;
use tc_f2m_custom_v2::{SecT163FieldElement, SecTCtCurve, SecTVarCurve};

type Ct<'a> = &'a SecTCtCurve<SecT163FieldElement>;
type Var<'a> = &'a SecTVarCurve<SecT163FieldElement>;

fn field<F: FieldElement>(criterion: &mut Criterion, name: &str, x: F, y: F) {
    let mut group = criterion.benchmark_group("multiply");
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| black_box(&x).multiply(black_box(&y)))
    });
    group.finish();

    let mut group = criterion.benchmark_group("square");
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| black_box(&x).square())
    });
    group.finish();

    let mut group = criterion.benchmark_group("invert");
    group.bench_with_input(BenchmarkId::from_parameter(name), &(), |b, _| {
        b.iter(|| black_box(&x).invert())
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

fn main() {
    let mut criterion = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15))
        .configure_from_args();
    let c = &mut criterion;

    let Ok(k) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&[
        0x03, 0x4F, 0x1D, 0x2C, 0x9B, 0x8A, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xF0, 0xE1,
        0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
    ]);

    let custom_ct = SECT163R2.ct_curve();
    let custom_g = SECT163R2.ct_generator(&custom_ct);
    let generic_ct = generic::SECT163R2.ct_curve();
    let generic_g = generic::SECT163R2.ct_generator(&generic_ct);

    field(c, "custom", custom_g.x().unwrap(), custom_g.y().unwrap());
    field(c, "generic", generic_g.x().unwrap(), generic_g.y().unwrap());

    multiply::<Ct<'_>>(c, "ct_multiply", "custom", &custom_g, &k);
    multiply::<&F2mCtCurve>(c, "ct_multiply", "generic", &generic_g, &k);

    let custom_var = SECT163R2.var_curve();
    let generic_var = generic::SECT163R2
        .var_curve()
        .with_coordinate_system(CoordinateSystem::LambdaProjective);
    multiply::<Var<'_>>(
        c,
        "var_multiply",
        "custom",
        &SECT163R2.var_generator(&custom_var),
        &k,
    );
    multiply::<&F2mVarCurve>(
        c,
        "var_multiply",
        "generic",
        &generic::SECT163R2.var_generator(&generic_var),
        &k,
    );

    criterion.final_summary();
}
