//! RSA-2048 on every engine of the crate, and key generation on both
//! generators. Windows of at least 15 seconds keep the noise down:
//!
//! ```text
//! cargo bench -p tc_rsa_v2 --features rustcrypto --bench rsa2048 -- --warm-up-time 3 --measurement-time 15
//! ```

#[path = "../tests/common/mod.rs"]
mod common;

use std::hint::black_box;

use common::{BLOCK, D, DP, DQ, N, P, Q, Q_INV, bytes};
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rsa::{BoxedUint, RsaPrivateKey, RsaPublicKey};
use tc_asym_cipher::{
    AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
    KeyPairGeneratorInit,
};
use tc_bigint::{ArrayEncoding, FixedBigUint, PaddedBigUint, Word};
use tc_rsa_v2::{
    FixedRsaCoreEngine, FixedRsaCrtCoreEngine, PaddedRsaCoreEngine, PaddedRsaCrtCoreEngine,
    RsaCoreEngineRustCrypto, RsaCrtCoreEngineRustCrypto, RsaError, RsaKeyGenerationParamsOwned,
    RsaKeyOwned, RsaKeyPairGenerator, RsaKeyPairGeneratorRustCrypto, RsaKeyRustCrypto,
    RsaPrivateCrtKeyOwned, RsaPrivateCrtKeyRustCrypto,
};

const WIDE: usize = 2048 / Word::BITS as usize;
const HALF: usize = 1024 / Word::BITS as usize;
type U2048 = FixedBigUint<WIDE>;
type U1024 = FixedBigUint<HALF>;

/// Times one block through `engine`; the keys, the engines and the buffers
/// are all set up before the timing starts.
fn bench_engine(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    engine: &mut impl AsymmetricBlockCipher<Error = RsaError>,
) {
    let mut output = [0; 256];
    group.bench_function(name, |b| {
        b.iter(|| {
            let length = engine
                .process_block(black_box(&BLOCK), black_box(&mut output))
                .unwrap();
            black_box(&output[..length]);
        });
    });
}

fn engines(c: &mut Criterion) {
    let [n, e, d, p, q, dp, dq, q_inv] = [N, "010001", D, P, Q, DP, DQ, Q_INV].map(bytes);
    let wide = |value: &[u8]| U2048::from_be(value).unwrap();
    let half = |value: &[u8]| U1024::from_be(value).unwrap();
    let padded = |value: &[u8]| PaddedBigUint::from_be(value).unwrap();
    let boxed = BoxedUint::from_be_slice_vartime;

    let mut group = c.benchmark_group("public");
    let mut fixed = FixedRsaCoreEngine::new();
    fixed
        .init(
            CipherDirection::Encrypt,
            &RsaKeyOwned::new(false, wide(&n), wide(&e)),
        )
        .unwrap();
    bench_engine(&mut group, "fixed", &mut fixed);
    let mut padded_engine = PaddedRsaCoreEngine::new();
    padded_engine
        .init(
            CipherDirection::Encrypt,
            &RsaKeyOwned::new(false, padded(&n), padded(&e)),
        )
        .unwrap();
    bench_engine(&mut group, "padded", &mut padded_engine);
    let mut rustcrypto = RsaCoreEngineRustCrypto::new();
    let public = RsaKeyRustCrypto::new(RsaPublicKey::new(boxed(&n), boxed(&e)).unwrap());
    rustcrypto.init(CipherDirection::Encrypt, &public).unwrap();
    bench_engine(&mut group, "rustcrypto", &mut rustcrypto);
    group.finish();

    let mut group = c.benchmark_group("private_plain");
    let mut fixed = FixedRsaCoreEngine::new();
    fixed
        .init(
            CipherDirection::Decrypt,
            &RsaKeyOwned::new(true, wide(&n), wide(&d)),
        )
        .unwrap();
    bench_engine(&mut group, "fixed", &mut fixed);
    let mut padded_engine = PaddedRsaCoreEngine::new();
    padded_engine
        .init(
            CipherDirection::Decrypt,
            &RsaKeyOwned::new(true, padded(&n), padded(&d)),
        )
        .unwrap();
    bench_engine(&mut group, "padded", &mut padded_engine);
    group.finish();

    let mut group = c.benchmark_group("private_crt");
    let mut fixed = FixedRsaCrtCoreEngine::new();
    let key = RsaPrivateCrtKeyOwned::new(
        wide(&n),
        wide(&e),
        wide(&d),
        half(&p),
        half(&q),
        half(&dp),
        half(&dq),
        half(&q_inv),
    );
    fixed.init(CipherDirection::Decrypt, &key).unwrap();
    bench_engine(&mut group, "fixed", &mut fixed);
    let mut padded_engine = PaddedRsaCrtCoreEngine::new();
    let key = RsaPrivateCrtKeyOwned::new(
        padded(&n),
        padded(&e),
        padded(&d),
        padded(&p),
        padded(&q),
        padded(&dp),
        padded(&dq),
        padded(&q_inv),
    );
    padded_engine.init(CipherDirection::Decrypt, &key).unwrap();
    bench_engine(&mut group, "padded", &mut padded_engine);
    let mut rustcrypto = RsaCrtCoreEngineRustCrypto::new();
    let key =
        RsaPrivateKey::from_components(boxed(&n), boxed(&e), boxed(&d), vec![boxed(&p), boxed(&q)])
            .unwrap();
    rustcrypto
        .init(
            CipherDirection::Decrypt,
            &RsaPrivateCrtKeyRustCrypto::new(key).unwrap(),
        )
        .unwrap();
    bench_engine(&mut group, "rustcrypto", &mut rustcrypto);
    group.finish();
}

fn key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");
    group.sample_size(10);
    let mut seed = 0;
    let mut params = move || {
        seed += 1;
        RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(seed))
    };
    group.bench_function("fixed", |b| {
        b.iter(|| {
            let mut generator = RsaKeyPairGenerator::<U2048, U1024>::new();
            generator.init(params()).unwrap();
            black_box(generator.generate_key_pair().unwrap());
        });
    });
    group.bench_function("padded", |b| {
        b.iter(|| {
            let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
            generator.init(params()).unwrap();
            black_box(generator.generate_key_pair().unwrap());
        });
    });
    group.bench_function("rustcrypto", |b| {
        b.iter(|| {
            let mut generator = RsaKeyPairGeneratorRustCrypto::new();
            generator.init(params()).unwrap();
            black_box(generator.generate_key_pair().unwrap());
        });
    });
    group.finish();
}

criterion_group!(benches, engines, key_generation);
criterion_main!(benches);
