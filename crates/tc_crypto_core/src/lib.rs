//! Core cryptographic abstractions ported from Bouncy Castle's
//! `Org.BouncyCastle.Crypto` namespace.
//!
//! This crate holds the *traits* shared by the concrete digest and key-wrapper
//! algorithms that live in downstream crates. It is deliberately minimal and
//! dependency-free: unconditionally `no_std`, with no `alloc` requirement — the
//! traits describe fixed-size, streaming interfaces that need neither.
//!
//! Unlike `rand_core` (an external community trait we depend on), the digest and
//! XOF traits are ported here as **our own**, because the algorithms we port come
//! from Bouncy Castle and mirror its `IDigest` / `IXof` shapes.

// 正常建置為 no_std；測試時放行 std,好讓 `#[test]` 框架連結。真正的 no_std
// 驗證走 `cargo build`(非 test),見 README。
#![cfg_attr(not(test), no_std)]

// 只有需要擁有式輸出的 trait（Wrapper）才拉進 alloc；預設 build 不需要。
// 測試恆連結 std,故 test 時一併放行。
#[cfg(any(feature = "alloc", test))]
extern crate alloc;

pub mod digest;
pub mod xof;
#[cfg(any(feature = "alloc", test))]
pub mod wrapper;

pub use digest::{Digest, TryDigest};
pub use xof::{TryXof, Xof};
#[cfg(any(feature = "alloc", test))]
pub use wrapper::Wrapper;
