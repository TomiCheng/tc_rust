//! Concrete message-digest algorithms, ported from Bouncy Castle's
//! `Org.BouncyCastle.Crypto.Digests` namespace.
//!
//! Each algorithm implements the [`TryDigest`](tc_crypto_core::TryDigest) /
//! [`Digest`](tc_crypto_core::Digest) traits from `tc_crypto_core`. It depends only
//! on `tc_crypto_core` (never on `tc_math` — hashes carry no big-integer
//! arithmetic). Disable the default `std` feature for `no_std`; the standard
//! build can select architecture-specific acceleration at runtime. The crate
//! uses `alloc` only for the pass-through [`NullDigest`] and the runtime names
//! of [`KeccakDigest`] and [`Sha512tDigest`], every other digest is alloc-free.
//!
//! The real no_std build is verified by
//! `cargo build -p tc_digest --no-default-features` (tests link `std` for their
//! harness even when default features are disabled).

#![cfg_attr(not(any(test, feature = "std")), no_std)]

// `NullDigest` 需要無界累積緩衝(`Vec`),故整個 crate 為 no_std + alloc。
// 測試也明確從 alloc 取用 String/Vec/format!(見 no_std 測試註記)。
extern crate alloc;

pub mod blake2b;
pub mod dstu7564;
pub mod gost3411_2012;
mod md_buffer;
pub mod keccak;
pub mod md2;
pub mod md4;
pub mod null;
pub mod md5;
mod ripemd_common;
pub mod ripemd128;
pub mod ripemd160;
pub mod ripemd256;
pub mod ripemd320;
mod sha256_core;
mod sha512_core;
pub mod sha1;
pub mod sha224;
pub mod sha256;
pub mod sha3;
pub mod sha384;
pub mod sha512;
pub mod sha512t;
pub mod sm3;
pub mod tiger;
pub mod whirlpool;

pub use blake2b::Blake2bDigest;
pub use dstu7564::Dstu7564Digest;
pub use gost3411_2012::{Gost3411_2012_256Digest, Gost3411_2012_512Digest};
pub use keccak::KeccakDigest;
pub use md2::Md2Digest;
pub use md4::Md4Digest;
pub use null::NullDigest;
pub use md5::Md5Digest;
pub use ripemd128::RipeMD128Digest;
pub use ripemd160::RipeMD160Digest;
pub use ripemd256::RipeMD256Digest;
pub use ripemd320::RipeMD320Digest;
pub use sha1::Sha1Digest;
pub use sha224::Sha224Digest;
pub use sha256::Sha256Digest;
pub use sha3::Sha3Digest;
pub use sha384::Sha384Digest;
pub use sha512::Sha512Digest;
pub use sha512t::Sha512tDigest;
pub use sm3::Sm3Digest;
pub use tiger::TigerDigest;
pub use whirlpool::WhirlpoolDigest;
