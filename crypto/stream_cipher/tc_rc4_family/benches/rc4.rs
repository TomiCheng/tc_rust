//! RC4 portable 與 RustCrypto 後端的金鑰設定與 keystream 吞吐量。
//!
//! 執行 `cargo bench -p tc_rc4_family --bench rc4`，加上 `--features rustcrypto` 才會量 RustCrypto。
//! `--` 之後可接 Criterion 的篩選，例如 `-- 'rc4/process'`。
//!
//! 設定的 bench 以 16 bytes 金鑰重新 init 同一個引擎；處理的 bench 不含金鑰設定，持續推進同一條
//! keystream，回報 bytes/s。兩個後端都以秘密值當索引查表，都是變動時間，比較的是同樣的契約；這是
//! 效能量測，不是時間特性的驗證。

use std::{hint::black_box, time::Duration};

use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use tc_rc4_family::Rc4PortableEngine;
#[cfg(feature = "rustcrypto")]
use tc_rc4_family::Rc4RustCryptoEngine;
use tc_stream_cipher::{
    CipherDirection, InitError, KeyRef, StreamCipher, StreamCipherInit, StreamError,
};

/// 處理的訊息長度：一個小封包、一個封包、一個緩衝區。
const SIZES: [usize; 3] = [64, 1024, 16 * 1024];

const KEY: [u8; 16] = [0x42; 16];

trait Engine:
    StreamCipher<Error = StreamError> + for<'a> StreamCipherInit<KeyRef<'a>, Error = InitError>
{
}

impl<E> Engine for E where
    E: StreamCipher<Error = StreamError> + for<'a> StreamCipherInit<KeyRef<'a>, Error = InitError>
{
}

fn add_setup<E: Engine>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    backend: &str,
    create: fn() -> E,
) {
    let params = KeyRef::new(&KEY);
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
    create: fn() -> E,
) {
    for size in SIZES {
        let mut engine = create();
        engine
            .init(CipherDirection::Encrypt, &KeyRef::new(&KEY))
            .unwrap();
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

fn benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("rc4/init");
    group.throughput(Throughput::Elements(1));
    add_setup(&mut group, "portable", Rc4PortableEngine::new);
    #[cfg(feature = "rustcrypto")]
    add_setup(&mut group, "rustcrypto", Rc4RustCryptoEngine::new);
    group.finish();

    let mut group = c.benchmark_group("rc4/process");
    add_process(&mut group, "portable", Rc4PortableEngine::new);
    #[cfg(feature = "rustcrypto")]
    add_process(&mut group, "rustcrypto", Rc4RustCryptoEngine::new);
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15));
    targets = benchmarks
}
criterion_main!(benches);
