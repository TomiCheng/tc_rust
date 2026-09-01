//! AES single-block throughput benchmarks.
//!
//! `cargo bench -p tc_aes --bench aes`
//!
//! `AesEngine` picks its backend from the processor, so which one was measured
//! is reported in the benchmark's name. Build with `force-portable-aes` to
//! measure its portable T-table backend instead. `AesLightEngine` is always
//! portable, and is here to show what the small-footprint representation costs.

use std::hint::black_box;

use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use tc_aes::{AesEngine, AesLightEngine, BLOCK_BYTES, KEY_BYTES};
use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_params::{KeyParams, KeyRef};

/// Names the backend `AesEngine` will actually select on this processor.
fn backend_name() -> &'static str {
    #[cfg(not(feature = "force-portable-aes"))]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    // 這是 bench,可以直接用 std 的偵測;函式庫本身走 core 的 CPUID。
    if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2") {
        return "aes-ni";
    }
    "portable"
}

fn key(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| (index as u8).wrapping_mul(0x3d).wrapping_add(0x17))
        .collect()
}

fn input_block() -> [u8; BLOCK_BYTES] {
    core::array::from_fn(|index| (index as u8).wrapping_mul(0x0b).wrapping_add(0x29))
}

/// Times one initialised engine over a single block, for every key length.
fn add_benches<E>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    implementation: &str,
    direction: CipherDirection,
    create: impl Fn() -> E,
) where
    E: BlockCipher<Error = BlockError>
        + for<'a> BlockCipherInit<Params<'a> = dyn KeyParams + 'a, Error = InitError>,
{
    for key_size in KEY_BYTES {
        let key = key(key_size);
        let params = KeyRef::new(&key);

        // 解密要餵真的密文,免得量到的是別的東西。
        let mut input = input_block();
        if direction == CipherDirection::Decrypt {
            let mut encryptor = AesEngine::new();
            encryptor.init(CipherDirection::Encrypt, &params).unwrap();
            let mut ciphertext = [0u8; BLOCK_BYTES];
            encryptor.process_block(&input, &mut ciphertext).unwrap();
            input = ciphertext;
        }

        let mut engine = create();
        engine.init(direction, &params).unwrap();
        let mut output = [0u8; BLOCK_BYTES];

        group.bench_function(BenchmarkId::new(implementation, key_size * 8), |b| {
            b.iter(|| {
                let produced = engine
                    .process_block(black_box(&input), black_box(&mut output))
                    .unwrap();
                black_box((produced, output));
            });
        });
    }
}

fn bench_direction(c: &mut Criterion, direction: CipherDirection, name: &str) {
    let mut group = c.benchmark_group(format!("aes/{name}"));
    group.throughput(Throughput::Bytes(BLOCK_BYTES as u64));

    add_benches(
        &mut group,
        &format!("AesEngine-{}", backend_name()),
        direction,
        AesEngine::new,
    );
    add_benches(
        &mut group,
        "AesLightEngine-portable",
        direction,
        AesLightEngine::new,
    );

    group.finish();
}

fn bench_encrypt(c: &mut Criterion) {
    bench_direction(c, CipherDirection::Encrypt, "encrypt");
}

fn bench_decrypt(c: &mut Criterion) {
    bench_direction(c, CipherDirection::Decrypt, "decrypt");
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
