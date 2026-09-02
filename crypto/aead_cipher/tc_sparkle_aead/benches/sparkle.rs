//! SCHWAEMM256-256 encryption throughput benchmark.
//!
//! Run with runtime SSE2 dispatch:
//! `cargo bench -p tc_sparkle_aead --bench sparkle`
//!
//! Run the same workload through the portable fallback:
//! `cargo bench -p tc_sparkle_aead --bench sparkle --features disable-x86-sse2`

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
use tc_sparkle_aead::{Engine, Params, Variant};

const INPUT_SIZES: [usize; 3] = [32, 1024, 64 * 1024];

fn backend_name() -> &'static str {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if tc_runtime::intrinsics::x86::Sse2::is_enabled() {
        return "sse2";
    }

    "portable"
}

fn input(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(17))
        .collect()
}

fn bench_encrypt(c: &mut Criterion) {
    let key = core::array::from_fn::<_, 32, _>(|index| index as u8);
    let nonce = core::array::from_fn::<_, 32, _>(|index| (index as u8).wrapping_add(32));
    let aad = core::array::from_fn::<_, 32, _>(|index| (index as u8).wrapping_add(64));
    let mut group = c.benchmark_group(format!(
        "sparkle/schwaemm256-256/encrypt/{}",
        backend_name()
    ));

    for size in INPUT_SIZES {
        let plaintext = input(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, input| {
            b.iter_batched(
                || {
                    let params = Params::new(&key, &nonce, &[]);
                    let mut engine = Engine::new(Variant::Schwaemm256_256);
                    engine.init(CipherDirection::Encrypt, &params).unwrap();
                    engine.process_aad_bytes(&aad).unwrap();
                    let output = vec![0_u8; engine.get_output_size(input.len())];
                    (engine, output)
                },
                |(mut engine, mut output)| {
                    let mut written = engine
                        .process_bytes(black_box(input), black_box(&mut output))
                        .unwrap();
                    written += engine.do_final(&mut output[written..]).unwrap();
                    black_box((engine, output, written))
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);
