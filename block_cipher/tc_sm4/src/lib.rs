//! SM4 single-block encryption with 128-bit keys and blocks.
//!
//! Variable time: key expansion and block processing use secret-dependent
//! S-box lookups. Use only where cache-timing leakage is outside the threat
//! model; this crate provides no constant-time alternative.
//!
//! Stored round keys are wiped on drop, but caller buffers and every register
//! or stack copy are not. No mode, padding or authentication is provided.

#![no_std]

mod cipher;
mod engine;

pub use engine::Sm4Engine;

/// SM4 block length in bytes.
pub const BLOCK_BYTES: usize = 16;
/// SM4 key length in bytes.
pub const KEY_BYTES: usize = 16;
/// Algorithm name written by the engine.
pub const ALGO_NAME: &str = "SM4";
