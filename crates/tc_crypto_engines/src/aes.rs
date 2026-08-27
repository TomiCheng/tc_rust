//! AES-128, AES-192, and AES-256 block cipher.
//!
//! The portable implementation is always available. With the default `std`
//! feature on x86/x86_64, [`AesEngine`] detects AES-NI at runtime and uses it
//! when available. Builds without default features always use the portable
//! backend.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{AesEngine, AesParams};
//!
//! let params = AesParams::new(&[0u8; 16])?;
//! let mut cipher = AesEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut output = [0u8; 16];
//! cipher.process_block(&[0u8; 16], &mut output)?;
//! # Ok::<(), tc_crypto_engines::AesError>(())
//! ```

mod engine;
mod params;
mod portable;

#[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
mod x86;

pub use engine::AesEngine;
pub use params::AesParams;

use core::fmt;

/// AES block length in bytes (128 bits).
pub const AES_BLOCK_BYTES: usize = 16;

pub(crate) const MAX_ROUND_KEYS: usize = 15;
pub(crate) type RoundKeys = [[u8; AES_BLOCK_BYTES]; MAX_ROUND_KEYS];

/// An error from AES parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AesError {
    /// The key was not 16, 24, or 32 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one AES block.
    BufferTooShort,
}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => {
                write!(f, "AES key must be 16, 24, or 32 bytes, got {n}")
            }
            Self::NotInitialised => write!(f, "AES engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one AES block"),
        }
    }
}

impl core::error::Error for AesError {}
