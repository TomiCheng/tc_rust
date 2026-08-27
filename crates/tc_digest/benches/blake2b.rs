//! BLAKE2b end-to-end throughput benchmarks.
//!
//! Run the runtime-dispatched std backend:
//! `cargo bench -p tc_digest --bench blake2b`
//!
//! Run the portable backend with `tc_digest` compiled as `no_std`:
//! `cargo bench -p tc_digest --bench blake2b --no-default-features`

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tc_crypto_core::Digest;
use tc_digest::Blake2bDigest;

const INPUT_SIZES: [usize; 5] = [64, 128, 1024, 64 * 1024, 1024 * 1024];

fn backend_name() -> &'static str {
    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    if std::is_x86_feature_detected!("avx2") {
        return "avx2";
    }

    #[cfg(feature = "std")]
    {
        "std-portable"
    }

    #[cfg(not(feature = "std"))]
    {
        "no_std-portable"
    }
}

fn input(size: usize) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(17))
        .collect()
}

fn bench_unkeyed(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("blake2b/unkeyed/{}", backend_name()));

    for size in INPUT_SIZES {
        let data = input(size);
        let mut digest = Blake2bDigest::new();
        let mut output = [0u8; 64];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                digest.update(black_box(data));
                digest.do_final(black_box(&mut output));
                black_box(output);
            });
        });
    }

    group.finish();
}

fn bench_keyed(c: &mut Criterion) {
    let key: Vec<u8> = (0..64).collect();
    let mut group = c.benchmark_group(format!("blake2b/keyed/{}", backend_name()));

    for size in INPUT_SIZES {
        let data = input(size);
        let mut digest = Blake2bDigest::with_key(&key);
        let mut output = [0u8; 64];

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                digest.update(black_box(data));
                digest.do_final(black_box(&mut output));
                black_box(output);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_unkeyed, bench_keyed);
criterion_main!(benches);
