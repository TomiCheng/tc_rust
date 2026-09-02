//! Poly1305 message authentication code.
//!
//! This crate implements raw Poly1305 with a caller-supplied 32-byte one-time
//! key. It does not implement the optional block-cipher construction.

#![no_std]

mod engine;

pub use engine::Engine;

/// Poly1305 input block length in bytes.
pub const BLOCK_BYTES: usize = 16;
/// Poly1305 one-time key length in bytes.
pub const KEY_BYTES: usize = 32;
/// Poly1305 authentication-tag length in bytes.
pub const TAG_BYTES: usize = 16;
