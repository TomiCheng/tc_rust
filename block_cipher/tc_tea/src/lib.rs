//! TEA and XTEA single-block ciphers with big-endian key and block words.
//!
//! Import `tc_block_cipher::{BlockCipher, BlockCipherInit}` to use either engine.
//! The two algorithms are not compatible. Neither supplies modes, padding or authentication.

#![no_std]

mod cipher;
mod tea_engine;
mod xtea_engine;

pub use tea_engine::TeaEngine;
pub use xtea_engine::XteaEngine;

/// Block length in bytes.
pub const BLOCK_BYTES: usize = 8;
/// Required key length in bytes.
pub const KEY_BYTES: usize = 16;
/// TEA's display name.
pub const TEA_ALGO_NAME: &str = "TEA";
/// XTEA's display name.
pub const XTEA_ALGO_NAME: &str = "XTEA";
