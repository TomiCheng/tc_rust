//! Key-wrapping algorithms ported from Bouncy Castle's `IWrapper` family.
//!
//! A key wrapper encrypts *key material* (rather than arbitrary plaintext) under
//! a key-encryption key, producing a slightly longer wrapped blob that carries
//! its own integrity check, so a tampered or wrong-key blob is rejected on
//! unwrap. Each algorithm builds on a block cipher from [`tc_block_cipher`] and
//! reports failures through this crate's own error type.

// 關閉預設 feature 時為 no_std；測試仍讓 `#[test]` 框架連結 std。
#![cfg_attr(not(any(feature = "std", test)), no_std)]

// Wrap/Unwrap 會回傳新配置的位元組緩衝區，故整個 crate 為 no_std + alloc。
extern crate alloc;

pub mod rfc3394;

pub use rfc3394::{Rfc3394Params, Rfc3394WrapEngine};
