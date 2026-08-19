//! `mod_pow` 效能對照：現行的 Barrett 版 vs 舊的逐步 `% m` 版。
//!
//! 跑：`cargo bench -p tc_math`
//! 基準線 `mod_pow_simple` 只用公開 API 重寫舊演算法，好跟現行 `mod_pow` 並排比。

use tc_math::big_integer::BigInteger;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

/// 舊版：逐位平方-乘，每步用全長 `% m` 約簡（Barrett 之前的做法）。
fn mod_pow_simple(base: &BigInteger, e: &BigInteger, m: &BigInteger) -> BigInteger {
    let b = base.rem_euclid(m);
    let mut result = BigInteger::from_u32(1);
    for i in (0..e.bit_length()).rev() {
        result = &result.square() % m;
        if e.test_bit(i) {
            result = &(&result * &b) % m;
        }
    }
    result
}

// 512-bit 的測試數字（m 為奇數，貼近 RSA 模數）。
const M_HEX: &str = "828619d8197b0aa510dae10a542e5b5538f5bfd4f4b763dbb15e9ffcad82876047a802e0c1a302daac2e77cb0bcde79f629356e5d92cf65106f94fad13b84ecf";
const BASE_HEX: &str = "74222cb1acdc0054b29e00b186c9086bb83298bdd7742ed40da3a44aaefd63335618ac4d08aaa5d503e4fca46e196ee82b49aa633096fd1a1cc80b0f82658d1b";
const E_HEX: &str = "395f8b61502138bc19a82cb3d3b16bcded651b9587c1ac25e545fe11e7bf073df5f26509b6da9c904c8b9da69f8e70ae9decaf87833cd23d4e7e7b8c457276b2";

fn bench_mod_pow(c: &mut Criterion) {
    let m = BigInteger::from_str_radix(M_HEX, 16).unwrap();
    let base = BigInteger::from_str_radix(BASE_HEX, 16).unwrap();
    let e = BigInteger::from_str_radix(E_HEX, 16).unwrap();

    let mut g = c.benchmark_group("mod_pow_512bit");
    g.bench_function("barrett", |bch| {
        bch.iter(|| black_box(&base).mod_pow(black_box(&e), black_box(&m)))
    });
    g.bench_function("simple_percent", |bch| {
        bch.iter(|| mod_pow_simple(black_box(&base), black_box(&e), black_box(&m)))
    });
    g.finish();
}

criterion_group!(benches, bench_mod_pow);
criterion_main!(benches);
