//! XTEA (eXtended TEA) 64-bit block cipher, ported from Bouncy Castle's
//! `XteaEngine`.
//!
//! XTEA fixes TEA's key-schedule weaknesses by interleaving the key words
//! differently each round. This port precomputes the two 32-word round-key
//! schedules (`sum0`/`sum1`) at [`init`](tc_crypto_core::BlockCipher::init).
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{XteaEngine, XteaParams};
//!
//! let key = [0u8; 16];
//! let params = XteaParams::new(&key)?;
//! let mut cipher = XteaEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 8];
//! cipher.process_block(&[0u8; 8], &mut ciphertext)?;
//! assert_eq!(ciphertext, [0xde, 0xe9, 0xd4, 0xd8, 0xf7, 0x13, 0x1e, 0xd9]);
//! # Ok::<(), tc_crypto_engines::XteaError>(())
//! ```

mod engine;
mod params;

pub use engine::XteaEngine;
pub use params::XteaParams;

use core::fmt;

/// XTEA key length in bytes (128 bits).
pub const XTEA_KEY_BYTES: usize = 16;
/// XTEA block length in bytes (64 bits).
pub const XTEA_BLOCK_BYTES: usize = 8;

/// An error from XTEA parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XteaError {
    /// The key was not exactly 16 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one block.
    BufferTooShort,
}

impl fmt::Display for XteaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => {
                write!(f, "XTEA key must be {XTEA_KEY_BYTES} bytes, got {n}")
            }
            Self::NotInitialised => write!(f, "XTEA engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one XTEA block"),
        }
    }
}

impl core::error::Error for XteaError {}
