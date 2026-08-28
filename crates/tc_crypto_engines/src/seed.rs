//! SEED 128-bit block cipher (RFC 4009), ported from Bouncy Castle's
//! `SeedEngine`.
//!
//! SEED is a 16-round Feistel cipher with a 128-bit key and 128-bit block,
//! operating on two 64-bit halves. The round function `F` and key schedule are
//! driven by four 256-entry S-box tables `SS0..SS3`.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{SeedEngine, SeedParams};
//!
//! let key = [0u8; 16];
//! let params = SeedParams::new(&key)?;
//! let mut cipher = SeedEngine::new();
//! cipher.init(true, &params)?;
//!
//! let plaintext = [
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//! ];
//! let mut ciphertext = [0u8; 16];
//! cipher.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x5E, 0xBA, 0xC6, 0xE0, 0x05, 0x4E, 0x16, 0x68,
//!     0x19, 0xAF, 0xF1, 0xCC, 0x6D, 0x34, 0x6C, 0xDB,
//! ]);
//! # Ok::<(), tc_crypto_engines::SeedError>(())
//! ```

mod engine;
mod params;
mod tables;

pub use engine::SeedEngine;
pub use params::SeedParams;

use core::fmt;

/// SEED key length in bytes (128 bits).
pub const SEED_KEY_BYTES: usize = 16;
/// SEED block length in bytes (128 bits).
pub const SEED_BLOCK_BYTES: usize = 16;

/// An error from SEED parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedError {
    /// The key was not exactly 16 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one block.
    BufferTooShort,
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => {
                write!(f, "SEED key must be {SEED_KEY_BYTES} bytes, got {n}")
            }
            Self::NotInitialised => write!(f, "SEED engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one SEED block"),
        }
    }
}

impl core::error::Error for SeedError {}
