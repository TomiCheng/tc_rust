//! Salsa20 與 XSalsa20 portable 與 RustCrypto 後端的金鑰設定與 keystream 吞吐量。
//!
//! 執行 `cargo bench -p tc_salsa20 --bench salsa20`，加上 `--features rustcrypto` 才會量 RustCrypto。
//! `--` 之後可接 Criterion 的篩選，例如 `-- 'salsa20/salsa20/process'`。
//!
//! 設定的 bench 以 32 bytes 金鑰重新 init 同一個引擎，XSalsa20 包含 HSalsa20。處理的 bench 不含金鑰
//! 設定，持續推進同一條 keystream，回報 bytes/s。兩個後端都是常數時間，比較的是同樣的契約；這是效能
//! 量測，不是常數時間的驗證。

use std::{hint::black_box, time::Duration};

use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use tc_salsa20::{Salsa20PortableEngine, Xsalsa20PortableEngine};
#[cfg(feature = "rustcrypto")]
use tc_salsa20::{Salsa20RustCryptoEngine, Xsalsa20RustCryptoEngine};
use tc_stream_cipher::{
    CipherDirection, InitError, KeyWithIvRef, StreamCipher, StreamCipherInit, StreamError,
};

/// 處理的訊息長度：一個區塊、一個封包、一個緩衝區。
const SIZES: [usize; 3] = [64, 1024, 16 * 1024];

trait Engine:
    StreamCipher<Error = StreamError> + for<'a> StreamCipherInit<KeyWithIvRef<'a>, Error = InitError>
{
}

impl<E> Engine for E where
    E: StreamCipher<Error = StreamError>
        + for<'a> StreamCipherInit<KeyWithIvRef<'a>, Error = InitError>
{
}

const KEY: [u8; 32] = [0x42; 32];
const IV: [u8; 24] = [0x24; 24];

fn add_setup<E: Engine>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    backend: &str,
    iv_bytes: usize,
    create: fn() -> E,
) {
    let params = KeyWithIvRef::new(&KEY, &IV[..iv_bytes]);
    let mut engine = create();
    group.bench_function(backend, |b| {
        b.iter(|| {
            engine
                .init(CipherDirection::Encrypt, black_box(&params))
                .unwrap();
            black_box(&mut engine);
        });
    });
}

fn add_process<E: Engine>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    backend: &str,
    iv_bytes: usize,
    create: fn() -> E,
) {
    for size in SIZES {
        let mut engine = create();
        let params = KeyWithIvRef::new(&KEY, &IV[..iv_bytes]);
        engine.init(CipherDirection::Encrypt, &params).unwrap();
        let input = vec![0x5a; size];
        let mut output = vec![0; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::new(backend, size), |b| {
            b.iter(|| {
                let written = engine
                    .process_bytes(black_box(&input), black_box(&mut output))
                    .unwrap();
                black_box(written);
                black_box(&output);
            });
        });
    }
}

/// 為一個變體註冊設定與處理兩組 bench；`$rustcrypto` 只在開了 feature 時存在。
macro_rules! bench_variant {
    ($c:expr, $name:literal, $portable:ident, $rustcrypto:ident) => {{
        let iv_bytes = $portable::IV_BYTES;

        let mut group = $c.benchmark_group(concat!("salsa20/", $name, "/init"));
        group.throughput(Throughput::Elements(1));
        add_setup(&mut group, "portable", iv_bytes, $portable::new);
        #[cfg(feature = "rustcrypto")]
        add_setup(&mut group, "rustcrypto", iv_bytes, $rustcrypto::new);
        group.finish();

        let mut group = $c.benchmark_group(concat!("salsa20/", $name, "/process"));
        add_process(&mut group, "portable", iv_bytes, $portable::new);
        #[cfg(feature = "rustcrypto")]
        add_process(&mut group, "rustcrypto", iv_bytes, $rustcrypto::new);
        group.finish();
    }};
}

fn benchmarks(c: &mut Criterion) {
    bench_variant!(c, "salsa20", Salsa20PortableEngine, Salsa20RustCryptoEngine);
    bench_variant!(
        c,
        "xsalsa20",
        Xsalsa20PortableEngine,
        Xsalsa20RustCryptoEngine
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15));
    targets = benchmarks
}
criterion_main!(benches);
