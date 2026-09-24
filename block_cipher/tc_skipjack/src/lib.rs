//! SKIPJACK single-block encryption with an 80-bit key and 64-bit blocks.
//!
//! Variable time: block processing uses secret-dependent F-table lookups.
//! Use only where cache-timing leakage is outside the threat model; this crate
//! provides no constant-time alternative. Stored schedules are wiped on drop,
//! but caller buffers and every register or stack copy are not.
//!
//! No mode, padding or authentication is provided.

#![no_std]

mod cipher;
mod engine;

pub use engine::SkipjackEngine;

/// SKIPJACK block length in bytes.
pub const BLOCK_BYTES: usize = 8;
/// SKIPJACK key length in bytes.
pub const KEY_BYTES: usize = 10;
/// Algorithm name written by the engine.
pub const ALGO_NAME: &str = "SKIPJACK";
