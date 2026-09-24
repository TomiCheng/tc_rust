//! SEED single-block encryption with a 128-bit key and 128-bit blocks.
//!
//! [`SeedEngine`] uses the same working key for encryption and decryption,
//! traversing its sixteen Feistel rounds in opposite orders.
//! Variable time: key setup and block processing index SS0-SS3 S-box tables
//! with secret data. Use only where cache-timing leakage is outside the
//! threat model; this crate provides no constant-time alternative.
//!
//! The stored working key is wiped on drop. This does not wipe caller buffers
//! or guarantee erasure of every register or stack copy. This allocator-free
//! crate provides no mode, padding or authentication.

#![no_std]

mod cipher;
mod engine;

pub use engine::SeedEngine;

/// SEED block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// SEED key length in bytes (128 bits).
pub const KEY_BYTES: usize = 16;
/// Algorithm name written by the engine's display implementation.
pub const ALGO_NAME: &str = "SEED";
