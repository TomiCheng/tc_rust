use core::hint::black_box;
use core::time::Duration;

use criterion::{Criterion, Throughput};
use tc_digest::{Digest, Xof};
use tc_keccak::{Sha3Digest, ShakeDigest};

fn main() {
    let mut criterion = Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(15))
        .configure_from_args();
    let c = &mut criterion;

    // 一次 do_final：短訊息時間幾乎都花在置換
    let mut group = c.benchmark_group("sha3-256");
    for size in [64, 1024, 16384] {
        let message = vec![0x5a; size];
        let mut output = [0; 32];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}"), |b| {
            let mut sha3 = Sha3Digest::new(256);
            b.iter(|| {
                sha3.update(black_box(&message));
                sha3.do_final(&mut output);
            })
        });
    }
    group.finish();

    // 擠出：每個 rate 區塊一次置換
    let mut group = c.benchmark_group("shake128/output");
    for size in [1024, 16384] {
        let mut output = vec![0; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}"), |b| {
            let mut shake = ShakeDigest::new(128);
            b.iter(|| {
                shake.update(b"seed");
                shake.output_final(black_box(&mut output));
            })
        });
    }
    group.finish();

    // Ed448 簽章的雜湊形狀：dom4 加 57 bytes 加短訊息，擠出 114 bytes
    c.bench_function("shake256/ed448-sized", |b| {
        let mut shake = ShakeDigest::new(256);
        let input = [0x5a; 10 + 57 + 32];
        let mut output = [0; 114];
        b.iter(|| {
            shake.update(black_box(&input));
            shake.output_final(&mut output);
        })
    });
}
