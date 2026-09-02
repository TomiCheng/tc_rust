//! CAST6 (CAST-256) block cipher.

mod cipher;
mod engine;

pub use engine::Cast6Engine;

/// CAST6 block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// Supported CAST6 key lengths in bytes.
pub const KEY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];
