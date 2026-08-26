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

mod md_buffer;
pub mod md2;
pub mod md4;

pub use md2::Md2Digest;
pub use md4::Md4Digest;
