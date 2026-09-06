//! 代表性 SEC 特化 Solinas 欄位與通用 Montgomery 欄位的 Jacobian 標量乘基準線。

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use tc_bigint::{U256, U384};
use tc_ec_core::{CoordinateSystem, wnaf_mul_point};
use tc_fp_curve::FpCurve;
use tc_fp_custom::{
    SecP256K1Curve, SecP256R1Curve, SecP384R1Curve, secp256k1, secp256r1, secp384r1,
};

fn benchmark(c: &mut Criterion) {
    let scalar = U256::from_be_bytes(&[
        0xd3, 0x5f, 0x8a, 0x71, 0x90, 0xc4, 0x2e, 0x16, 0xaa, 0x55, 0x63, 0x9b, 0x17, 0xe2, 0x4c,
        0x81, 0xf0, 0x3d, 0x77, 0x29, 0x68, 0xb4, 0x10, 0xce, 0x52, 0x91, 0x44, 0xef, 0x83, 0x0a,
        0xbd, 0x67,
    ])
    .unwrap();
    let (_, custom_point) = secp256r1();
    let (generic_curve, affine_point) = tc_fp_curve::named_curves::secp256r1();
    let generic_curve = Arc::new(
        generic_curve
            .as_ref()
            .clone()
            .with_coordinate_system(CoordinateSystem::Jacobian),
    );
    let generic_point = generic_curve.create_point(
        affine_point.x().unwrap().to_big_uint(),
        affine_point.y().unwrap().to_big_uint(),
    );

    c.bench_function("secp256r1/custom/wnaf_mul", |b| {
        b.iter(|| wnaf_mul_point::<SecP256R1Curve>(black_box(&custom_point), black_box(&scalar)))
    });
    c.bench_function("secp256r1/generic_montgomery/wnaf_mul", |b| {
        b.iter(|| wnaf_mul_point::<FpCurve<U256>>(black_box(&generic_point), black_box(&scalar)))
    });

    let (custom_curve, custom_point) = secp256k1();
    let (generic_curve, affine_point) = tc_fp_curve::named_curves::secp256k1();
    let generic_curve = Arc::new(
        generic_curve
            .as_ref()
            .clone()
            .with_coordinate_system(CoordinateSystem::Jacobian),
    );
    let generic_point = generic_curve.create_point(
        affine_point.x().unwrap().to_big_uint(),
        affine_point.y().unwrap().to_big_uint(),
    );
    let scalar = *custom_curve.order() - U256::from(1_u8);
    c.bench_function("secp256k1/custom/wnaf_mul", |b| {
        b.iter(|| wnaf_mul_point::<SecP256K1Curve>(black_box(&custom_point), black_box(&scalar)))
    });
    c.bench_function("secp256k1/generic_montgomery/wnaf_mul", |b| {
        b.iter(|| wnaf_mul_point::<FpCurve<U256>>(black_box(&generic_point), black_box(&scalar)))
    });

    let (custom_curve, custom_point) = secp384r1();
    let generic_curve = Arc::new(
        FpCurve::new(
            *custom_curve.q(),
            custom_curve.a().to_integer(),
            custom_curve.b().to_integer(),
            Some(*custom_curve.order()),
            Some(U384::from(1_u8)),
        )
        .with_coordinate_system(CoordinateSystem::Jacobian),
    );
    let generic_point = generic_curve.create_point(
        custom_point.x().unwrap().to_integer(),
        custom_point.y().unwrap().to_integer(),
    );
    let scalar = *custom_curve.order() - U384::from(1_u8);
    c.bench_function("secp384r1/custom/wnaf_mul", |b| {
        b.iter(|| wnaf_mul_point::<SecP384R1Curve>(black_box(&custom_point), black_box(&scalar)))
    });
    c.bench_function("secp384r1/generic_montgomery/wnaf_mul", |b| {
        b.iter(|| wnaf_mul_point::<FpCurve<U384>>(black_box(&generic_point), black_box(&scalar)))
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
