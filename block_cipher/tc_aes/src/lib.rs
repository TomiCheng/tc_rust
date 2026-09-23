#![no_std]

#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;

#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::AesRustCryptoEngine;

/// AES block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// Accepted key lengths in bytes (128, 192, and 256 bits).
pub const KEY_BYTES: [usize; 3] = [16, 24, 32];
