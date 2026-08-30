//! Core cryptographic abstractions ported from Bouncy Castle's
//! `Org.BouncyCastle.Crypto` namespace.
//!
//! This crate holds the digest and XOF traits shared by concrete algorithms in
//! downstream crates. It is deliberately minimal and dependency-free:
//! unconditionally `no_std`, with no `alloc` requirement.
//!
//! Unlike `rand_core` (an external community trait we depend on), the digest and
//! XOF traits are ported here as **our own**, because the algorithms we port come
//! from Bouncy Castle and mirror its `IDigest` / `IXof` shapes.

// 正常建置為 no_std；測試時放行 std,好讓 `#[test]` 框架連結。真正的 no_std
// 驗證走 `cargo build`(非 test),見 README。
#![cfg_attr(not(test), no_std)]

pub mod digest;
pub mod xof;

pub use digest::{Digest, TryDigest};
pub use xof::{TryXof, Xof};
