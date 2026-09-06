//! RFC 7748 的固定基點、通用 ladder 與欄位加減基準線。
//!
//! 預設啟用 x86 runtime 分派，X25519 欄位的 `apm` 會自動選擇 AVX2/SSE2。
//! 以 `--no-default-features` 重跑可取得純 scalar 基準線，直接比較分派收益。

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tc_rfc7748::{x448, x25519, x25519_field::Fe};

fn bench_x25519(c: &mut Criterion) {
    let scalar = [0xA5_u8; x25519::SCALAR_SIZE];
    let mut base = [0_u8; x25519::POINT_SIZE];
    base[0] = 9;
    let left = Fe::decode(&[0x55; x25519::POINT_SIZE]);
    let right = Fe::decode(&[0xA3; x25519::POINT_SIZE]);

    c.bench_function("rfc7748/x25519/scalar_mult", |b| {
        b.iter(|| x25519::scalar_mult(black_box(&scalar), black_box(&base)))
    });
    c.bench_function("rfc7748/x25519/scalar_mult_base", |b| {
        b.iter(|| x25519::scalar_mult_base(black_box(&scalar)))
    });
    c.bench_function("rfc7748/x25519/field_apm", |b| {
        b.iter(|| black_box(left).apm(black_box(right)))
    });
}

fn bench_x448(c: &mut Criterion) {
    let scalar = [0x5A_u8; x448::SCALAR_SIZE];
    let mut base = [0_u8; x448::POINT_SIZE];
    base[0] = 5;
    let a = tc_rfc7748::x448_field::Fe448::decode(&[0x55; 56]);
    let b = tc_rfc7748::x448_field::Fe448::decode(&[0xa3; 56]);
    c.bench_function("rfc7748/x448/field_mul", |bench| {
        bench.iter(|| black_box(a).mul(black_box(b)))
    });

    c.bench_function("rfc7748/x448/scalar_mult", |b| {
        b.iter(|| x448::scalar_mult(black_box(&scalar), black_box(&base)))
    });
    c.bench_function("rfc7748/x448/scalar_mult_base", |b| {
        b.iter(|| x448::scalar_mult_base(black_box(&scalar)))
    });
}

criterion_group!(benches, bench_x25519, bench_x448);
criterion_main!(benches);
