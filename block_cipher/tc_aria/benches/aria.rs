//! ARIA key setup and single-block benchmarks for all available engines.
//!
//! Run `cargo bench -p tc_aria --bench aria`, or add `--all-features` to
//! include RustCrypto. Optional Criterion filters follow `--`, for example
//! `-- 'aria/encrypt/table/128'`.
//!
//! Setup benchmarks reinitialise an existing engine, including replacement
//! of its old schedule; construction and final drop are outside the timing.
//! Block benchmarks exclude key setup and report bytes per second.
//! Only the Table and RustCrypto backends are measured, not the dispatcher.
//! These are performance measurements, not constant-time verification.

use std::{hint::black_box, time::Duration};

use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
#[cfg(feature = "rustcrypto")]
use tc_aria::AriaRustCryptoEngine;
use tc_aria::{AriaTableEngine, BLOCK_BYTES, KEY_BYTES};
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
};

fn add_engine<E>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    direction: CipherDirection,
    setup: bool,
    create: impl Fn() -> E,
) where
    E: BlockCipher<Error = BlockError> + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>,
{
    let plaintext = core::array::from_fn::<_, BLOCK_BYTES, _>(|i| i as u8);
    for key_len in KEY_BYTES {
        let key: Vec<u8> = (0..key_len).map(|i| (i as u8).wrapping_mul(0x3d)).collect();
        let params = KeyRef::new(&key);
        let mut encryptor = create();
        encryptor.init(CipherDirection::Encrypt, &params).unwrap();
        let mut ciphertext = [0; BLOCK_BYTES];
        encryptor
            .process_block(&plaintext, &mut ciphertext)
            .unwrap();
        let (input, expected) = match direction {
            CipherDirection::Encrypt => (plaintext, ciphertext),
            CipherDirection::Decrypt => (ciphertext, plaintext),
        };
        let mut engine = create();
        engine.init(direction, &params).unwrap();
        let mut output = [0; BLOCK_BYTES];
        assert_eq!(engine.process_block(&input, &mut output), Ok(BLOCK_BYTES));
        assert_eq!(output, expected);

        group.bench_function(BenchmarkId::new(name, key_len * 8), |b| {
            if setup {
                b.iter(|| {
                    engine
                        .init(black_box(direction), black_box(&params))
                        .unwrap();
                    black_box(&mut engine);
                });
            } else {
                b.iter(|| {
                    let written = engine
                        .process_block(black_box(&input), black_box(&mut output))
                        .unwrap();
                    black_box(written);
                    black_box(&output);
                });
            }
        });
    }
}

fn benchmarks(c: &mut Criterion) {
    for (operation, direction, setup) in [
        ("init-encrypt", CipherDirection::Encrypt, true),
        ("init-decrypt", CipherDirection::Decrypt, true),
        ("encrypt", CipherDirection::Encrypt, false),
        ("decrypt", CipherDirection::Decrypt, false),
    ] {
        let mut group = c.benchmark_group(format!("aria/{operation}"));
        if setup {
            group.throughput(Throughput::Elements(1));
        } else {
            group.throughput(Throughput::Bytes(BLOCK_BYTES as u64));
        }
        add_engine(&mut group, "table", direction, setup, AriaTableEngine::new);
        #[cfg(feature = "rustcrypto")]
        add_engine(
            &mut group,
            "rustcrypto",
            direction,
            setup,
            AriaRustCryptoEngine::new,
        );
        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15));
    targets = benchmarks
}
criterion_main!(benches);
