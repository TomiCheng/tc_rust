//! secp256r1 特化 Solinas 欄位與通用 Montgomery 欄位的標量乘基準線。

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tc_bigint::U256;
use tc_ec_core::wnaf_mul_point;
use tc_fp_curve::FpCurve;
use tc_fp_custom::{SecP256R1Curve, secp256r1};

fn benchmark(c: &mut Criterion) {
    let scalar = U256::from_be_bytes(&[
        0xd3, 0x5f, 0x8a, 0x71, 0x90, 0xc4, 0x2e, 0x16, 0xaa, 0x55, 0x63, 0x9b, 0x17, 0xe2, 0x4c,
        0x81, 0xf0, 0x3d, 0x77, 0x29, 0x68, 0xb4, 0x10, 0xce, 0x52, 0x91, 0x44, 0xef, 0x83, 0x0a,
        0xbd, 0x67,
    ])
    .unwrap();
    let (_, custom_point) = secp256r1();
    let (_, generic_point) = tc_fp_curve::named_curves::secp256r1();

    c.bench_function("secp256r1/custom/wnaf_mul", |b| {
        b.iter(|| wnaf_mul_point::<SecP256R1Curve>(black_box(&custom_point), black_box(&scalar)))
    });
    c.bench_function("secp256r1/generic_montgomery/wnaf_mul", |b| {
        b.iter(|| wnaf_mul_point::<FpCurve<U256>>(black_box(&generic_point), black_box(&scalar)))
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
