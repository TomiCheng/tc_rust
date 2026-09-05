//! Focused comparisons for reducer shape and Karatsuba cutoffs.
//!
//! Run with:
//! `cargo bench -p tc_binpoly --bench tuning --features bench-internals`

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use tc_binpoly::bench_support::{
    BenchReducer, karatsuba_scratch_size, scalar_multiply_with_cutoff,
};

#[cfg(all(feature = "x86", any(target_arch = "x86", target_arch = "x86_64")))]
use tc_binpoly::bench_support::x86_multiply_with_cutoff;

fn words(len: usize, factor: u64) -> Vec<u64> {
    (0..len)
        .map(|i| {
            factor
                .wrapping_mul(i as u64 + 1)
                .rotate_left((i * 11) as u32)
        })
        .collect()
}

fn bench_reducer_shapes(c: &mut Criterion) {
    let reducers = [
        ("tri-113-9", 113, BenchReducer::trinomial(113, 9)),
        ("tri-193-15", 193, BenchReducer::trinomial(193, 15)),
        ("tri-233-74", 233, BenchReducer::trinomial(233, 74)),
        ("tri-239-158", 239, BenchReducer::trinomial(239, 158)),
        ("tri-409-87", 409, BenchReducer::trinomial(409, 87)),
        (
            "penta-131-2-3-8",
            131,
            BenchReducer::pentanomial(131, 2, 3, 8),
        ),
        (
            "penta-163-3-6-7",
            163,
            BenchReducer::pentanomial(163, 3, 6, 7),
        ),
        (
            "penta-283-5-7-12",
            283,
            BenchReducer::pentanomial(283, 5, 7, 12),
        ),
        (
            "penta-571-2-5-10",
            571,
            BenchReducer::pentanomial(571, 2, 5, 10),
        ),
    ];

    let mut group = c.benchmark_group("binpoly/tuning/reducer");
    for (label, n, reducer) in reducers {
        let len = (n + 63) >> 6;
        let mut x = words(len, 0x9E37_79B9_7F4A_7C15);
        let mut y = words(len, 0xD1B5_4A32_D192_ED03);
        if n & 63 != 0 {
            let mask = (1_u64 << (n & 63)) - 1;
            x[len - 1] &= mask;
            y[len - 1] &= mask;
        }
        let mut product = vec![0_u64; len * 2];
        tc_binpoly::scalar::impl_mul(&x, &y, &mut product);
        let mut z = vec![0_u64; len];

        group.bench_function(BenchmarkId::new(label, "reduce_words"), |b| {
            b.iter_batched(
                || product.clone(),
                |mut tt| reducer.reduce_words(black_box(&mut tt), black_box(&mut z)),
                BatchSize::SmallInput,
            )
        });
        group.bench_function(BenchmarkId::new(label, "bc_shape"), |b| {
            b.iter_batched(
                || product.clone(),
                |mut tt| reducer.reduce_bc_shape(black_box(&mut tt), black_box(&mut z)),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_scalar_cutoffs(c: &mut Criterion) {
    const LENGTHS: &[usize] = &[6, 8, 9, 12, 16, 24, 32];
    const CUTOFFS: &[usize] = &[4, 6, 8, 10, 12, 16];
    let mut group = c.benchmark_group("binpoly/tuning/scalar-cutoff");

    for &len in LENGTHS {
        let x = words(len, 0x9E37_79B9_7F4A_7C15);
        let y = words(len, 0xD1B5_4A32_D192_ED03);
        for cutoff in core::iter::once(len + 1).chain(CUTOFFS.iter().copied().filter(|&c| c <= len))
        {
            let label = if cutoff > len {
                "medium".to_owned()
            } else {
                format!("cutoff-{cutoff}")
            };
            let mut zz = vec![0_u64; len * 2];
            let mut scratch = vec![0_u64; karatsuba_scratch_size(len, cutoff)];
            group.bench_function(BenchmarkId::new(format!("len-{len}"), label), |b| {
                b.iter(|| {
                    scalar_multiply_with_cutoff(
                        black_box(&x),
                        black_box(&y),
                        black_box(&mut zz),
                        black_box(&mut scratch),
                        cutoff,
                    )
                })
            });
        }
    }
    group.finish();
}

#[cfg(all(feature = "x86", any(target_arch = "x86", target_arch = "x86_64")))]
fn bench_x86_cutoffs(c: &mut Criterion) {
    const LENGTHS: &[usize] = &[24, 32, 48, 64, 72, 80, 88, 96, 112, 128];
    const CUTOFFS: &[usize] = &[24, 32, 48, 64, 80, 96];
    let mut group = c.benchmark_group("binpoly/tuning/x86-cutoff");

    for &len in LENGTHS {
        let x = words(len, 0x9E37_79B9_7F4A_7C15);
        let y = words(len, 0xD1B5_4A32_D192_ED03);
        for cutoff in core::iter::once(len + 1).chain(CUTOFFS.iter().copied().filter(|&c| c <= len))
        {
            let label = if cutoff > len {
                "medium".to_owned()
            } else {
                format!("cutoff-{cutoff}")
            };
            let mut zz = vec![0_u64; len * 2];
            let mut scratch = vec![0_u64; karatsuba_scratch_size(len, cutoff)];
            group.bench_function(BenchmarkId::new(format!("len-{len}"), label), |b| {
                b.iter(|| {
                    assert!(x86_multiply_with_cutoff(
                        black_box(&x),
                        black_box(&y),
                        black_box(&mut zz),
                        black_box(&mut scratch),
                        cutoff,
                    ));
                })
            });
        }
    }
    group.finish();
}

#[cfg(not(all(feature = "x86", any(target_arch = "x86", target_arch = "x86_64"))))]
fn bench_x86_cutoffs(_: &mut Criterion) {}

criterion_group!(
    benches,
    bench_reducer_shapes,
    bench_scalar_cutoffs,
    bench_x86_cutoffs
);
criterion_main!(benches);
