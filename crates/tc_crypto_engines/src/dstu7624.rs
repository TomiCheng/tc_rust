//! DSTU 7624:2014 (Kalyna) block cipher.
//!
//! The engine is configured for a 128-, 256-, or 512-bit block when created.
//! A key may be the same size as the block or twice its size, subject to the
//! standard's 512-bit maximum key size.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{Dstu7624Engine, Dstu7624Params};
//!
//! let key: [u8; 16] = core::array::from_fn(|index| index as u8);
//! let input: [u8; 16] = core::array::from_fn(|index| index as u8 + 0x10);
//! let params = Dstu7624Params::new(&key)?;
//! let mut cipher = Dstu7624Engine::new(128)?;
//! cipher.init(true, &params)?;
//!
//! let mut output = [0u8; 16];
//! cipher.process_block(&input, &mut output)?;
//! assert_eq!(output, [
//!     0x81, 0xBF, 0x1C, 0x7D, 0x77, 0x9B, 0xAC, 0x20,
//!     0xE1, 0xC9, 0xEA, 0x39, 0xB4, 0xD2, 0xAD, 0x06,
//! ]);
//! # Ok::<(), tc_crypto_engines::Dstu7624Error>(())
//! ```

mod cipher;
mod engine;
mod params;
mod tables;

pub use engine::Dstu7624Engine;
pub use params::Dstu7624Params;

use core::fmt;

/// Supported DSTU 7624 block lengths in bits.
pub const DSTU7624_BLOCK_BITS: [usize; 3] = [128, 256, 512];
/// Supported DSTU 7624 key lengths in bytes.
pub const DSTU7624_KEY_BYTES: [usize; 3] = [16, 32, 64];

/// An error from DSTU 7624 configuration, parameter validation, or processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dstu7624Error {
    /// The configured block size was not 128, 256, or 512 bits.
    InvalidBlockSize(usize),
    /// The key was not 16, 32, or 64 bytes.
    InvalidKeyLength(usize),
    /// The key length is valid in isolation but not for the configured block.
    UnsupportedKeyForBlock {
        /// Configured block length in bits.
        block_bits: usize,
        /// Supplied key length in bits.
        key_bits: usize,
    },
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one configured block.
    BufferTooShort,
}

impl fmt::Display for Dstu7624Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize(bits) => write!(
                f,
                "DSTU 7624 block must contain 128, 256, or 512 bits, got {bits}"
            ),
            Self::InvalidKeyLength(bytes) => write!(
                f,
                "DSTU 7624 key must contain 16, 32, or 64 bytes, got {bytes}"
            ),
            Self::UnsupportedKeyForBlock {
                block_bits,
                key_bits,
            } => write!(
                f,
                "DSTU 7624 does not support a {key_bits}-bit key with a {block_bits}-bit block"
            ),
            Self::NotInitialised => write!(f, "DSTU 7624 engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one DSTU 7624 block"),
        }
    }
}

impl core::error::Error for Dstu7624Error {}
