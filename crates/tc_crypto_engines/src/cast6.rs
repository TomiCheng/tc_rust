//! CAST6 (CAST-256) block cipher.
//!
//! CAST6 uses a 128-bit block and 128-, 160-, 192-, 224-, or 256-bit keys.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{Cast6Engine, Cast6Params};
//!
//! let key = [
//!     0x23, 0x42, 0xBB, 0x9E, 0xFA, 0x38, 0x54, 0x2C,
//!     0x0A, 0xF7, 0x56, 0x47, 0xF2, 0x9F, 0x61, 0x5D,
//! ];
//! let params = Cast6Params::new(&key)?;
//! let mut cipher = Cast6Engine::new();
//! cipher.init(true, &params)?;
//!
//! let mut output = [0u8; 16];
//! cipher.process_block(&[0u8; 16], &mut output)?;
//! assert_eq!(output, [
//!     0xC8, 0x42, 0xA0, 0x89, 0x72, 0xB4, 0x3D, 0x20,
//!     0x83, 0x6C, 0x91, 0xD1, 0xB7, 0x53, 0x0F, 0x6B,
//! ]);
//! # Ok::<(), tc_crypto_engines::Cast6Error>(())
//! ```

mod cipher;
mod engine;
mod params;

pub use engine::Cast6Engine;
pub use params::Cast6Params;

use core::fmt;

/// CAST6 block length in bytes (128 bits).
pub const CAST6_BLOCK_BYTES: usize = 16;
/// Supported CAST6 key lengths in bytes.
pub const CAST6_KEY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];

/// An error from CAST6 parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cast6Error {
    /// The key was not 16, 20, 24, 28, or 32 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one CAST6 block.
    BufferTooShort,
}

impl fmt::Display for Cast6Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => write!(
                f,
                "CAST6 key must contain 16, 20, 24, 28, or 32 bytes, got {n}"
            ),
            Self::NotInitialised => write!(f, "CAST6 engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one CAST6 block"),
        }
    }
}

impl core::error::Error for Cast6Error {}
