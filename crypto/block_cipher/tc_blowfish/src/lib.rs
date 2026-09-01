//! Blowfish block cipher.

#![no_std]

mod cipher;
mod engine;

pub use engine::BlowfishEngine;

/// Blowfish block length in bytes (64 bits).
pub const BLOCK_BYTES: usize = 8;
/// Minimum Blowfish key length in bytes (32 bits).
pub const MIN_KEY_BYTES: usize = 4;
/// Maximum Blowfish key length in bytes (448 bits).
pub const MAX_KEY_BYTES: usize = 56;
