//! Twofish single-block encryption with 128-, 192- and 256-bit keys.
//!
//! Variable time: key-dependent S-box and MDS lookups, and key-setup branches,
//! depend on secret data. Use only where timing leakage is outside the threat
//! model; no constant-time alternative is provided. Stored tables and subkeys
//! are wiped on drop, but caller buffers and every register or stack copy
//! are not. No mode, padding or authentication is provided.

#![no_std]

mod cipher;
mod engine;

pub use engine::TwofishEngine;

/// Twofish block length in bytes.
pub const BLOCK_BYTES: usize = 16;
/// Accepted Twofish key lengths in bytes.
pub const KEY_BYTES: [usize; 3] = [16, 24, 32];
/// Algorithm name written by the engine.
pub const ALGO_NAME: &str = "Twofish";
