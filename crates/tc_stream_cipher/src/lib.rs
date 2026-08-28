//! Stream cipher implementations ported from Bouncy Castle's engine package.
//!
//! All engines implement the [`StreamCipher`](tc_crypto_core::StreamCipher) trait
//! from `tc_crypto_core`. Each algorithm owns its parameter type (validated key,
//! and nonce where applicable) and reports failures through its own error type.
//!
//! Stream ciphers keep fixed-size keystream state, so this crate is `no_std`
//! with no `alloc` requirement.

// 關閉預設 feature 時為 no_std；測試仍讓 `#[test]` 框架連結 std。
#![cfg_attr(not(any(feature = "std", test)), no_std)]

pub mod rc4;

pub use rc4::{RC4_MAX_KEY_BYTES, Rc4Engine, Rc4Error, Rc4Params};
