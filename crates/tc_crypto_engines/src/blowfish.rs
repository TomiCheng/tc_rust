//! Blowfish block cipher with 32- to 448-bit keys.
//!
//! Blowfish has a 64-bit block and is retained mainly for compatibility with
//! legacy data and protocols. New designs should use a modern cipher with a
//! larger block size.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{BlowfishEngine, BlowfishParams};
//!
//! let params = BlowfishParams::new(&[0u8; 8])?;
//! let mut cipher = BlowfishEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut output = [0u8; 8];
//! cipher.process_block(&[0u8; 8], &mut output)?;
//! assert_eq!(output, [0x4E, 0xF9, 0x97, 0x45, 0x61, 0x98, 0xDD, 0x78]);
//! # Ok::<(), tc_crypto_engines::BlowfishError>(())
//! ```

mod cipher;
mod engine;
mod params;

pub use engine::BlowfishEngine;
pub use params::BlowfishParams;

use core::fmt;

/// Blowfish block length in bytes (64 bits).
pub const BLOWFISH_BLOCK_BYTES: usize = 8;
/// Minimum Blowfish key length in bytes (32 bits).
pub const BLOWFISH_MIN_KEY_BYTES: usize = 4;
/// Maximum Blowfish key length in bytes (448 bits).
pub const BLOWFISH_MAX_KEY_BYTES: usize = 56;

/// An error from Blowfish parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlowfishError {
    /// The key was outside the 4- to 56-byte range.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one Blowfish block.
    BufferTooShort,
}

impl fmt::Display for BlowfishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => {
                write!(f, "Blowfish key must be between 4 and 56 bytes, got {n}")
            }
            Self::NotInitialised => write!(f, "Blowfish engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one Blowfish block"),
        }
    }
}

impl core::error::Error for BlowfishError {}
