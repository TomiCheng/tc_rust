//! TEA (Tiny Encryption Algorithm) 64-bit block cipher, ported from Bouncy
//! Castle's `TeaEngine`.
//!
//! TEA uses a 128-bit key and a 64-bit block over 32 rounds, driven by the
//! golden-ratio constant `delta`. The two 32-bit words are big-endian.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{TeaEngine, TeaParams};
//!
//! let key = [0u8; 16];
//! let params = TeaParams::new(&key)?;
//! let mut cipher = TeaEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 8];
//! cipher.process_block(&[0u8; 8], &mut ciphertext)?;
//! assert_eq!(ciphertext, [0x41, 0xea, 0x3a, 0x0a, 0x94, 0xba, 0xa9, 0x40]);
//! # Ok::<(), tc_crypto_engines::TeaError>(())
//! ```

mod engine;
mod params;

pub use engine::TeaEngine;
pub use params::TeaParams;

use core::fmt;

/// TEA key length in bytes (128 bits).
pub const TEA_KEY_BYTES: usize = 16;
/// TEA block length in bytes (64 bits).
pub const TEA_BLOCK_BYTES: usize = 8;

/// An error from TEA parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TeaError {
    /// The key was not exactly 16 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one block.
    BufferTooShort,
}

impl fmt::Display for TeaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => {
                write!(f, "TEA key must be {TEA_KEY_BYTES} bytes, got {n}")
            }
            Self::NotInitialised => write!(f, "TEA engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one TEA block"),
        }
    }
}

impl core::error::Error for TeaError {}
