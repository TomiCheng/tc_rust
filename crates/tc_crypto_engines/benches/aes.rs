//! AES single-block throughput benchmarks.
//!
//! Run the runtime-dispatched std backend:
//! `cargo bench -p tc_crypto_engines --bench aes`
//!
//! Run the portable backend with `tc_crypto_engines` compiled as `no_std`:
//! `cargo bench -p tc_crypto_engines --bench aes --no-default-features`

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tc_crypto_core::BlockCipher;
use tc_crypto_engines::{AES_BLOCK_BYTES, AesEngine, AesParams};

const KEY_SIZES: [usize; 3] = [16, 24, 32];

fn backend_name() -> &'static str {
    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2") {
        return "aes-ni";
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

fn key(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| (index as u8).wrapping_mul(0x3D).wrapping_add(0x17))
        .collect()
}

fn input_block() -> [u8; AES_BLOCK_BYTES] {
    core::array::from_fn(|index| (index as u8).wrapping_mul(0x0B).wrapping_add(0x29))
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("aes/encrypt/{}", backend_name()));
    group.throughput(Throughput::Bytes(AES_BLOCK_BYTES as u64));

    for key_size in KEY_SIZES {
        let params = AesParams::new(&key(key_size)).unwrap();
        let mut engine = AesEngine::new();
        engine.init(true, &params).unwrap();
        let input = input_block();
        let mut output = [0u8; AES_BLOCK_BYTES];

        group.bench_function(BenchmarkId::new("key-bits", key_size * 8), |b| {
            b.iter(|| {
                let produced = engine
                    .process_block(black_box(&input), black_box(&mut output))
                    .unwrap();
                black_box((produced, output));
            });
        });
    }

    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("aes/decrypt/{}", backend_name()));
    group.throughput(Throughput::Bytes(AES_BLOCK_BYTES as u64));

    for key_size in KEY_SIZES {
        let params = AesParams::new(&key(key_size)).unwrap();
        let mut encryptor = AesEngine::new();
        encryptor.init(true, &params).unwrap();
        let mut ciphertext = [0u8; AES_BLOCK_BYTES];
        encryptor
            .process_block(&input_block(), &mut ciphertext)
            .unwrap();

        let mut engine = AesEngine::new();
        engine.init(false, &params).unwrap();
        let mut output = [0u8; AES_BLOCK_BYTES];

        group.bench_function(BenchmarkId::new("key-bits", key_size * 8), |b| {
            b.iter(|| {
                let produced = engine
                    .process_block(black_box(&ciphertext), black_box(&mut output))
                    .unwrap();
                black_box((produced, output));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
