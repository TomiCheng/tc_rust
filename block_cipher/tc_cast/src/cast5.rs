//! CAST5 (CAST-128) block cipher.

mod cipher;
mod engine;
mod tables;

pub use engine::Cast5Engine;

/// CAST5 block length in bytes (64 bits).
/// Constant time: this value is public and independent of key material.
pub const BLOCK_BYTES: usize = 8;
/// Minimum CAST5 key length in bytes (40 bits).
/// Constant time: this value is public and independent of key material.
pub const MIN_KEY_BYTES: usize = 5;
/// Maximum CAST5 key length in bytes (128 bits).
/// Constant time: this value is public and independent of key material.
pub const MAX_KEY_BYTES: usize = 16;

/// Algorithm display name. Constant time: independent of key material.
pub const ALGO_NAME: &str = "CAST5";
