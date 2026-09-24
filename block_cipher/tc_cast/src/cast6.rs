//! CAST6 (CAST-256) block cipher.

mod cipher;
mod engine;

pub use engine::Cast6Engine;

/// CAST6 block length in bytes (128 bits).
/// Constant time: this value is public and independent of key material.
pub const BLOCK_BYTES: usize = 16;
/// Supported CAST6 key lengths in bytes.
/// Constant time: this value is public and independent of key material.
pub const KEY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];

/// Algorithm display name. Constant time: independent of key material.
pub const ALGO_NAME: &str = "CAST6";
