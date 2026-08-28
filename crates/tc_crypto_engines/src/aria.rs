//! ARIA-128, ARIA-192, and ARIA-256 block cipher as specified by RFC 5794.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{AriaEngine, AriaParams};
//!
//! let params = AriaParams::new(&[
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
//! ])?;
//! let mut cipher = AriaEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut output = [0u8; 16];
//! cipher.process_block(&[
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//!     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
//! ], &mut output)?;
//! assert_eq!(output, [
//!     0xD7, 0x18, 0xFB, 0xD6, 0xAB, 0x64, 0x4C, 0x73,
//!     0x9D, 0xA9, 0x5F, 0x3B, 0xE6, 0x45, 0x17, 0x78,
//! ]);
//! # Ok::<(), tc_crypto_engines::AriaError>(())
//! ```

mod cipher;
mod engine;
mod params;

pub use engine::AriaEngine;
pub use params::AriaParams;

use core::fmt;

/// ARIA block length in bytes (128 bits).
pub const ARIA_BLOCK_BYTES: usize = 16;

pub(crate) const ARIA_MAX_ROUND_KEYS: usize = 17;
pub(crate) type AriaRoundKeys = [[u8; ARIA_BLOCK_BYTES]; ARIA_MAX_ROUND_KEYS];

/// An error from ARIA parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AriaError {
    /// The key was not 16, 24, or 32 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one ARIA block.
    BufferTooShort,
}

impl fmt::Display for AriaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => {
                write!(f, "ARIA key must be 16, 24, or 32 bytes, got {n}")
            }
            Self::NotInitialised => write!(f, "ARIA engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one ARIA block"),
        }
    }
}

impl core::error::Error for AriaError {}
