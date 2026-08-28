//! Data Encryption Standard (DES), ported from Bouncy Castle's `DesEngine`.
//!
//! DES has an 8-byte block and an 8-byte encoded key (56 effective key bits;
//! the least-significant bit of each key byte is conventionally an odd-parity
//! bit). Keys are passed through exactly as supplied.
//!
//! DES is retained for compatibility with legacy protocols. Its 56-bit key is
//! not secure for new applications.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{DesEngine, DesParams};
//!
//! let params = DesParams::new(&[0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1])?;
//! let mut cipher = DesEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut output = [0u8; 8];
//! cipher.process_block(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF], &mut output)?;
//! assert_eq!(output, [0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05]);
//! # Ok::<(), tc_crypto_engines::DesError>(())
//! ```

mod cipher;
mod engine;
mod params;

pub(crate) use cipher::{des_func, generate_working_key};
pub use engine::DesEngine;
pub use params::DesParams;

use core::fmt;

/// DES key length in bytes (64 encoded bits, 56 effective bits).
pub const DES_KEY_BYTES: usize = 8;
/// DES block length in bytes (64 bits).
pub const DES_BLOCK_BYTES: usize = 8;

/// An error from DES parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DesError {
    /// The key was not exactly 8 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one DES block.
    BufferTooShort,
}

impl fmt::Display for DesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => write!(f, "DES key must be 8 bytes, got {n}"),
            Self::NotInitialised => write!(f, "DES engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one DES block"),
        }
    }
}

impl core::error::Error for DesError {}
