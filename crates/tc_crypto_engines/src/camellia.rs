//! Camellia-128, Camellia-192, and Camellia-256 block cipher.
//!
//! [`CamelliaEngine`] is the four-T-table implementation corresponding to
//! Bouncy Castle's `CamelliaEngine`. [`CamelliaLightEngine`] uses a single
//! 256-byte S-box and computes the remaining transforms at runtime.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{CamelliaEngine, CamelliaParams};
//!
//! let key = [
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
//!     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
//! ];
//! let params = CamelliaParams::new(&key)?;
//! let mut cipher = CamelliaEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut output = [0u8; 16];
//! cipher.process_block(&key, &mut output)?;
//! assert_eq!(output, [
//!     0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
//!     0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE, 0x43,
//! ]);
//! # Ok::<(), tc_crypto_engines::CamelliaError>(())
//! ```

mod cipher;
mod engine;
mod light_engine;
mod params;

pub use engine::CamelliaEngine;
pub use light_engine::CamelliaLightEngine;
pub use params::CamelliaParams;

use core::fmt;

/// Camellia block length in bytes (128 bits).
pub const CAMELLIA_BLOCK_BYTES: usize = 16;

/// An error from Camellia parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CamelliaError {
    /// The key was not 16, 24, or 32 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one Camellia block.
    BufferTooShort,
}

impl fmt::Display for CamelliaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => {
                write!(f, "Camellia key must be 16, 24, or 32 bytes, got {n}")
            }
            Self::NotInitialised => write!(f, "Camellia engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one Camellia block"),
        }
    }
}

impl core::error::Error for CamelliaError {}
