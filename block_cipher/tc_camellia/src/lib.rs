//! Camellia single-block ciphers with standard and small-footprint engines.
//!
//! Both engines accept 16-, 24- and 32-byte keys and have a 16-byte block.
//! Import `tc_block_cipher::{BlockCipher, BlockCipherInit}` to initialize and use them.

#![no_std]

mod cipher;
mod engine;
mod light_engine;

pub use engine::CamelliaEngine;
pub use light_engine::CamelliaLightEngine;

/// Block length in bytes.
pub const BLOCK_BYTES: usize = 16;
/// Accepted key lengths in bytes.
pub const KEY_BYTES: [usize; 3] = [16, 24, 32];
/// Display name shared by both engines.
pub const ALGO_NAME: &str = "Camellia";
