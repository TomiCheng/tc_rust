//! Generalised Rijndael block cipher, ported from Bouncy Castle's
//! `RijndaelEngine` (the pre-NIST reference form).
//!
//! Unlike the AES engine, this supports the full Rijndael parameter space: block
//! and key sizes of 128, 160, 192, 224, or 256 bits in any combination. The block
//! size is fixed when the engine is created; the key size follows from the
//! [`RijndaelParams`] key length.
//!
//! The state is held as four 64-bit "rows" of `block_bits / 4` bits each, exactly
//! as the reference implementation packs it.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{RijndaelEngine, RijndaelParams};
//!
//! // 128-bit block, 128-bit key.
//! let key = [
//!     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//! let params = RijndaelParams::new(&key)?;
//! let mut cipher = RijndaelEngine::new(128)?;
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 16];
//! cipher.process_block(&[0u8; 16], &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x0E, 0xDD, 0x33, 0xD3, 0xC6, 0x21, 0xE5, 0x46,
//!     0x45, 0x5B, 0xD8, 0xBA, 0x14, 0x18, 0xBE, 0xC8,
//! ]);
//! # Ok::<(), tc_crypto_engines::RijndaelError>(())
//! ```

mod engine;
mod params;
mod tables;

pub use engine::RijndaelEngine;
pub use params::RijndaelParams;

use core::fmt;

/// Supported Rijndael block lengths in bits.
pub const RIJNDAEL_BLOCK_BITS: [usize; 5] = [128, 160, 192, 224, 256];
/// Supported Rijndael key lengths in bytes.
pub const RIJNDAEL_KEY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];

/// An error from Rijndael configuration, parameter validation, or processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RijndaelError {
    /// The configured block size was not 128/160/192/224/256 bits.
    InvalidBlockSize(usize),
    /// The key was not 16/20/24/28/32 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one configured block.
    BufferTooShort,
}

impl fmt::Display for RijndaelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize(bits) => write!(
                f,
                "Rijndael block must be 128/160/192/224/256 bits, got {bits}"
            ),
            Self::InvalidKeyLength(bytes) => write!(
                f,
                "Rijndael key must be 16/20/24/28/32 bytes, got {bytes}"
            ),
            Self::NotInitialised => write!(f, "Rijndael engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one Rijndael block"),
        }
    }
}

impl core::error::Error for RijndaelError {}
