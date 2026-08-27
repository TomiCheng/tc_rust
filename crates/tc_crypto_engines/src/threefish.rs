//! Threefish tweakable block cipher, ported from Bouncy Castle's
//! `ThreefishEngine` (Skein 1.3 / NIST SHA-3 submission).
//!
//! Threefish comes in three block sizes — 256, 512 and 1024 bits — where the key
//! is always the same size as the block, plus a fixed 128-bit tweak.

mod engine;
mod params;

pub use engine::ThreefishEngine;
pub use params::ThreefishParams;

use core::fmt;

/// The block size, in bits, of Threefish-256 (bc `BLOCKSIZE_256`).
pub const BLOCKSIZE_256: usize = 256;
/// The block size, in bits, of Threefish-512 (bc `BLOCKSIZE_512`).
pub const BLOCKSIZE_512: usize = 512;
/// The block size, in bits, of Threefish-1024 (bc `BLOCKSIZE_1024`).
pub const BLOCKSIZE_1024: usize = 1024;

/// The fixed tweak length, in bytes (128 bit), shared by all block sizes.
pub const TWEAK_BYTES: usize = 16;

/// An error from the Threefish cipher (bc's `ArgumentException` cases).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreefishError {
    /// The key length (bytes) is not a legal Threefish key size (32 / 64 / 128).
    InvalidKeyLength(usize),
    /// The tweak length (bytes) is not 16.
    InvalidTweakLength(usize),
}

impl fmt::Display for ThreefishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreefishError::InvalidKeyLength(n) => write!(
                f,
                "Threefish key must be 32, 64 or 128 bytes, got {n}"
            ),
            ThreefishError::InvalidTweakLength(n) => {
                write!(f, "Threefish tweak must be {TWEAK_BYTES} bytes, got {n}")
            }
        }
    }
}

impl core::error::Error for ThreefishError {}
