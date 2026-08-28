//! Triple DES (DES-EDE), ported from Bouncy Castle's `DesEdeEngine`.
//!
//! Both two-key (`K1, K2, K1`) and three-key (`K1, K2, K3`) forms are
//! supported. Key bytes, including parity bits and repeated or weak component
//! keys, are used exactly as supplied.
//!
//! Triple DES is retained for compatibility with legacy protocols and is not
//! recommended for new applications.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{DesEdeEngine, DesEdeParams};
//!
//! let params = DesEdeParams::new(&[
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
//!     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
//! ])?;
//! let mut cipher = DesEdeEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut output = [0u8; 8];
//! cipher.process_block(b"Now is t", &mut output)?;
//! assert_eq!(output, [0xD8, 0x0A, 0x0D, 0x8B, 0x2B, 0xAE, 0x5E, 0x4E]);
//! # Ok::<(), tc_crypto_engines::DesEdeError>(())
//! ```

mod engine;
mod params;

pub use engine::DesEdeEngine;
pub use params::DesEdeParams;

use core::fmt;

/// Triple DES block length in bytes.
pub const DES_EDE_BLOCK_BYTES: usize = 8;
/// Encoded key length for two-key Triple DES (`K1, K2, K1`).
pub const DES_EDE_TWO_KEY_BYTES: usize = 16;
/// Encoded key length for three-key Triple DES (`K1, K2, K3`).
pub const DES_EDE_THREE_KEY_BYTES: usize = 24;

/// An error from Triple DES parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DesEdeError {
    /// The key was neither 16 nor 24 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one Triple DES block.
    BufferTooShort,
}

impl fmt::Display for DesEdeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => {
                write!(f, "DESede key must be 16 or 24 bytes, got {n}")
            }
            Self::NotInitialised => write!(f, "DESede engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one DESede block"),
        }
    }
}

impl core::error::Error for DesEdeError {}
