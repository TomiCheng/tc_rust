//! ARIA-128, ARIA-192, and ARIA-256 block cipher as specified by RFC 5794.

#![no_std]

mod cipher;
mod engine;

pub use engine::AriaEngine;

/// ARIA block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;

const MAX_ROUND_KEYS: usize = 17;
type RoundKeys = [[u8; BLOCK_BYTES]; MAX_ROUND_KEYS];
