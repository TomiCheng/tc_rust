//! Concrete message-digest algorithms, ported from Bouncy Castle's
//! `Org.BouncyCastle.Crypto.Digests` namespace.
//!
//! Each algorithm implements the [`TryDigest`](tc_crypto_core::TryDigest) /
//! [`Digest`](tc_crypto_core::Digest) traits from `tc_crypto_core`. Digests are
//! pure fixed-size bit/byte computation, so this crate is `no_std` and needs no
//! `alloc`; it depends only on `tc_crypto_core` (never on `tc_math` — hashes carry
//! no big-integer arithmetic).
//!
//! The real no_std build is verified by `cargo build` (not `cargo test`, which
//! links `std` for the test harness).

#![cfg_attr(not(test), no_std)]

// 測試以 std 建置,但明確從 alloc 取用 String/Vec/format!,避免依賴「no_std 時消失、
// std 時才出現」的 prelude —— 否則 rust-analyzer 把 crate 當 no_std 分析時會誤標紅字。
#[cfg(test)]
extern crate alloc;

mod md_buffer;
pub mod md2;
pub mod md4;
pub mod md5;

pub use md2::Md2Digest;
pub use md4::Md4Digest;
pub use md5::Md5Digest;
