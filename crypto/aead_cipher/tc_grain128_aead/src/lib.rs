//! Grain-128AEAD authenticated encryption.

#![no_std]

mod engine;

pub use engine::Engine;

/// Secret-key length in bytes.
pub const KEY_BYTES: usize = 16;
/// Nonce length in bytes.
pub const NONCE_BYTES: usize = 12;
/// Authentication-tag length in bytes.
pub const TAG_BYTES: usize = 8;
