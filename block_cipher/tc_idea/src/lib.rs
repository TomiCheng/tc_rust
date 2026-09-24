//! IDEA single-block encryption with 128-bit keys and 64-bit blocks.
//!
//! Variable time: multiplication branches on secret values, and decryption
//! key setup uses key-dependent Euclidean inverses. Use only where timing
//! leakage is outside the threat model; no constant-time alternative is provided.
//! Stored schedules are wiped on drop, but caller buffers and every register
//! or stack copy are not. No mode, padding or authentication is provided.

#![no_std]

mod cipher;
mod engine;

pub use engine::IdeaEngine;

/// IDEA block length in bytes.
pub const BLOCK_BYTES: usize = 8;
/// IDEA key length in bytes.
pub const KEY_BYTES: usize = 16;
/// Algorithm name written by the engine.
pub const ALGO_NAME: &str = "IDEA";
