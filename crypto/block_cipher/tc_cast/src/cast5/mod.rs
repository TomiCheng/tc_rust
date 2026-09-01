//! CAST5 (CAST-128) block cipher.

mod cipher;
mod engine;
mod tables;

pub use engine::Cast5Engine;

/// CAST5 block length in bytes (64 bits).
pub const BLOCK_BYTES: usize = 8;
/// Minimum CAST5 key length in bytes (40 bits).
pub const MIN_KEY_BYTES: usize = 5;
/// Maximum CAST5 key length in bytes (128 bits).
pub const MAX_KEY_BYTES: usize = 16;
