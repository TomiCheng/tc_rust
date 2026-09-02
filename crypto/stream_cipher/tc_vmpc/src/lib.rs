//! VMPC stream ciphers.

#![no_std]

mod engine;

pub use engine::{VmpcEngine, VmpcKsa3Engine};

/// Minimum accepted key length in bytes.
pub const MIN_KEY_BYTES: usize = 16;
/// Maximum accepted key length in bytes.
pub const MAX_KEY_BYTES: usize = 64;
/// Minimum accepted IV length in bytes.
pub const MIN_IV_BYTES: usize = 16;
/// Maximum accepted IV length in bytes.
pub const MAX_IV_BYTES: usize = 64;
