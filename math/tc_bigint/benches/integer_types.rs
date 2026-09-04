//! Compares equivalent operations across all four integer representations.
//!
//! Run with: `cargo bench -p tc_bigint --bench integer_types`

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tc_bigint::modular::{FixedMontyForm, FixedMontyParams};
use tc_bigint::{BigInt, BigUint, FixedBigUint, I1024, ModMul, Odd, U1024, Word};

type U256 = FixedBigUint<{ 256 / Word::BITS as usize }>;

struct Values {
    big_uint: BigUint,
    big_int: BigInt,
    fixed_big_uint: U1024,
    fixed_big_int: I1024,
}

impl Values {
    fn from_unsigned_be_bytes(bytes: &[u8]) -> Self {
        Self {
            big_uint: BigUint::from_be_bytes(bytes),
            big_int: BigInt::from_unsigned_be_bytes(bytes),
            fixed_big_uint: U1024::from_be_bytes(bytes).expect("value fits U1024"),
            fixed_big_int: I1024::from_unsigned_be_bytes(bytes).expect("value fits I1024"),
        }
    }
}

fn patterned_bytes<const N: usize>(seed: u8, high: u8, odd: bool) -> [u8; N] {
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed
            .wrapping_add(index as u8)
            .wrapping_mul(0x9d)
            .rotate_left((index % 8) as u32);
    }
    bytes[0] = high;
    if odd {
        bytes[N - 1] |= 1;
    }
    bytes
}

fn bench_binary<T, R>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    lhs: &T,
    rhs: &T,
    mut operation: impl FnMut(&T, &T) -> R,
) {
    group.bench_function(name, |b| {
        b.iter(|| black_box(operation(black_box(lhs), black_box(rhs))))
    });
}

fn bench_ternary<T, R>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    first: &T,
    second: &T,
    third: &T,
    mut operation: impl FnMut(&T, &T, &T) -> R,
) {
    group.bench_function(name, |b| {
        b.iter(|| {
            black_box(operation(
                black_box(first),
                black_box(second),
                black_box(third),
            ))
        })
    });
}

fn bench_add(c: &mut Criterion) {
    let lhs = Values::from_unsigned_be_bytes(&patterned_bytes::<128>(0x31, 0x18, false));
    let rhs = Values::from_unsigned_be_bytes(&patterned_bytes::<128>(0x79, 0x08, false));
    let mut group = c.benchmark_group("add/1024-bit");

    bench_binary(
        &mut group,
        "BigUint",
        &lhs.big_uint,
        &rhs.big_uint,
        |a, b| a + b,
    );
    bench_binary(&mut group, "BigInt", &lhs.big_int, &rhs.big_int, |a, b| {
        a + b
    });
    bench_binary(
        &mut group,
        "FixedBigUint",
        &lhs.fixed_big_uint,
        &rhs.fixed_big_uint,
        |a, b| a + b,
    );
    bench_binary(
        &mut group,
        "FixedBigInt",
        &lhs.fixed_big_int,
        &rhs.fixed_big_int,
        |a, b| a + b,
    );
    group.finish();
}

fn bench_mul(c: &mut Criterion) {
    let lhs = Values::from_unsigned_be_bytes(&patterned_bytes::<64>(0x43, 0x40, false));
    let rhs = Values::from_unsigned_be_bytes(&patterned_bytes::<64>(0xa7, 0x20, false));
    let mut group = c.benchmark_group("mul/512x512-bit");

    bench_binary(
        &mut group,
        "BigUint",
        &lhs.big_uint,
        &rhs.big_uint,
        |a, b| a * b,
    );
    bench_binary(&mut group, "BigInt", &lhs.big_int, &rhs.big_int, |a, b| {
        a * b
    });
    bench_binary(
        &mut group,
        "FixedBigUint",
        &lhs.fixed_big_uint,
        &rhs.fixed_big_uint,
        |a, b| a * b,
    );
    bench_binary(
        &mut group,
        "FixedBigInt",
        &lhs.fixed_big_int,
        &rhs.fixed_big_int,
        |a, b| a * b,
    );
    group.finish();
}

fn bench_large_mul(c: &mut Criterion) {
    for byte_len in [256, 512] {
        let mut lhs_bytes = vec![0_u8; byte_len];
        let mut rhs_bytes = vec![0_u8; byte_len];
        for (index, byte) in lhs_bytes.iter_mut().enumerate() {
            *byte = 0x43_u8
                .wrapping_add(index as u8)
                .wrapping_mul(0x9d)
                .rotate_left((index % 8) as u32);
        }
        for (index, byte) in rhs_bytes.iter_mut().enumerate() {
            *byte = 0xa7_u8
                .wrapping_add(index as u8)
                .wrapping_mul(0x6b)
                .rotate_left((index % 8) as u32);
        }
        lhs_bytes[0] = 0xd3;
        rhs_bytes[0] = 0xb5;

        let lhs = BigUint::from_be_bytes(&lhs_bytes);
        let rhs = BigUint::from_be_bytes(&rhs_bytes);
        let bit_len = byte_len * 8;
        let mut group = c.benchmark_group(format!("mul/{bit_len}x{bit_len}-bit"));
        bench_binary(&mut group, "BigUint", &lhs, &rhs, |a, b| a * b);
        group.finish();

        let distinct_lhs = lhs.clone();
        let mut group = c.benchmark_group(format!("square/{bit_len}-bit"));
        group.bench_function("BigUint", |b| {
            b.iter(|| black_box(black_box(&lhs).square()))
        });
        bench_binary(
            &mut group,
            "BigUint multiply distinct clone",
            &lhs,
            &distinct_lhs,
            |a, b| a * b,
        );
        group.finish();
    }
}

fn bench_div(c: &mut Criterion) {
    let dividend = Values::from_unsigned_be_bytes(&patterned_bytes::<128>(0x59, 0x30, false));
    let divisor = Values::from_unsigned_be_bytes(&patterned_bytes::<64>(0x17, 0x40, true));
    let mut group = c.benchmark_group("div/1024-by-512-bit");

    bench_binary(
        &mut group,
        "BigUint",
        &dividend.big_uint,
        &divisor.big_uint,
        |a, b| a / b,
    );
    bench_binary(
        &mut group,
        "BigInt",
        &dividend.big_int,
        &divisor.big_int,
        |a, b| a / b,
    );
    bench_binary(
        &mut group,
        "FixedBigUint",
        &dividend.fixed_big_uint,
        &divisor.fixed_big_uint,
        |a, b| a / b,
    );
    bench_binary(
        &mut group,
        "FixedBigInt",
        &dividend.fixed_big_int,
        &divisor.fixed_big_int,
        |a, b| a / b,
    );
    group.finish();
}

fn bench_mod_pow(c: &mut Criterion) {
    let base = Values::from_unsigned_be_bytes(&patterned_bytes::<128>(0x83, 0x20, false));
    let exponent = Values::from_unsigned_be_bytes(&patterned_bytes::<32>(0x2d, 0x40, false));
    let modulus = Values::from_unsigned_be_bytes(&patterned_bytes::<128>(0xc1, 0x70, true));
    let mut group = c.benchmark_group("mod_pow/1024-bit-modulus-256-bit-exponent");

    bench_ternary(
        &mut group,
        "BigUint",
        &base.big_uint,
        &exponent.big_uint,
        &modulus.big_uint,
        |a, e, m| a.mod_pow(e, m),
    );
    bench_ternary(
        &mut group,
        "BigInt",
        &base.big_int,
        &exponent.big_int,
        &modulus.big_int,
        |a, e, m| a.mod_pow(e, m),
    );
    bench_ternary(
        &mut group,
        "FixedBigUint",
        &base.fixed_big_uint,
        &exponent.fixed_big_uint,
        &modulus.fixed_big_uint,
        |a, e, m| a.mod_pow(e, m),
    );
    bench_ternary(
        &mut group,
        "FixedBigInt",
        &base.fixed_big_int,
        &exponent.fixed_big_int,
        &modulus.fixed_big_int,
        |a, e, m| a.mod_pow(e, m),
    );
    group.finish();
}

fn bench_mod_mul(c: &mut Criterion) {
    let lhs_bytes = patterned_bytes::<32>(0x37, 0xd1, false);
    let rhs_bytes = patterned_bytes::<32>(0x91, 0xb3, false);
    let odd_modulus_bytes = patterned_bytes::<32>(0x53, 0xf1, true);
    let mut even_modulus_bytes = patterned_bytes::<32>(0x6b, 0xe7, false);
    even_modulus_bytes[31] &= !1;

    let big_lhs = BigUint::from_be_bytes(&lhs_bytes);
    let big_rhs = BigUint::from_be_bytes(&rhs_bytes);
    let big_modulus = BigUint::from_be_bytes(&odd_modulus_bytes);
    let fixed_lhs = U256::from_be_bytes(&lhs_bytes).expect("value fits U256");
    let fixed_rhs = U256::from_be_bytes(&rhs_bytes).expect("value fits U256");
    let fixed_odd_modulus = U256::from_be_bytes(&odd_modulus_bytes).expect("modulus fits U256");
    let fixed_even_modulus = U256::from_be_bytes(&even_modulus_bytes).expect("modulus fits U256");
    let odd_modulus = Odd::new(fixed_odd_modulus).expect("modulus is odd");
    let params = FixedMontyParams::new(odd_modulus);
    let monty_lhs = FixedMontyForm::new(&fixed_lhs, params);
    let monty_rhs = FixedMontyForm::new(&fixed_rhs, params);

    let mut group = c.benchmark_group("mod_mul/256-bit");
    bench_ternary(
        &mut group,
        "BigUint::mod_mul",
        &big_lhs,
        &big_rhs,
        &big_modulus,
        |a, b, m| a.mod_mul(b, m),
    );
    bench_ternary(
        &mut group,
        "BigUint naive multiply-rem",
        &big_lhs,
        &big_rhs,
        &big_modulus,
        |a, b, m| ((a % m) * (b % m)) % m,
    );
    bench_ternary(
        &mut group,
        "FixedBigUint::mod_mul/odd",
        &fixed_lhs,
        &fixed_rhs,
        &fixed_odd_modulus,
        |a, b, m| a.mod_mul(b, m),
    );
    bench_ternary(
        &mut group,
        "FixedBigUint::mod_mul/even",
        &fixed_lhs,
        &fixed_rhs,
        &fixed_even_modulus,
        |a, b, m| a.mod_mul(b, m),
    );
    bench_binary(
        &mut group,
        "FixedMontyForm::mul/reused-params",
        &monty_lhs,
        &monty_rhs,
        |a, b| a * b,
    );
    group.bench_function("FixedMontyParams::new", |b| {
        b.iter(|| black_box(FixedMontyParams::new(black_box(odd_modulus))))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_add,
    bench_mul,
    bench_large_mul,
    bench_div,
    bench_mod_pow,
    bench_mod_mul
);
criterion_main!(benches);
