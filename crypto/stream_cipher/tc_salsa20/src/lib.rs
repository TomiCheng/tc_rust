//! Salsa20 stream ciphers.
//!
//! The crate provides Salsa20 with selectable rounds and XSalsa20.

#![no_std]

mod engine;
mod salsa;
pub mod xsalsa20;

pub use engine::Salsa20Engine;
pub use xsalsa20::Xsalsa20Engine;

/// Default Salsa20 round count.
pub const DEFAULT_ROUNDS: usize = 20;
/// Salsa20 keystream-block length in bytes.
pub const BLOCK_BYTES: usize = 64;
/// Salsa20 IV length in bytes.
pub const IV_BYTES: usize = 8;
/// Supported Salsa20 key lengths in bytes.
pub const KEY_BYTES: [usize; 2] = [16, 32];

const MAX_ROUNDS: usize = i32::MAX as usize - 1;
