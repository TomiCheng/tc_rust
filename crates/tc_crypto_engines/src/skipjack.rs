//! SKIPJACK 64-bit block cipher, ported from Bouncy Castle's `SkipjackEngine`.
//!
//! SKIPJACK has an 80-bit (10-byte) key and 64-bit block, run over 32 steps that
//! alternate two "rules" (A and B), each built from the keyed `G` permutation and
//! a single byte-substitution `F`-table. Decryption uses the inverse permutation
//! `H` with the step counter reversed.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{SkipjackEngine, SkipjackParams};
//!
//! let key = [0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
//! let params = SkipjackParams::new(&key)?;
//! let mut cipher = SkipjackEngine::new();
//! cipher.init(true, &params)?;
//!
//! let plaintext = [0x33, 0x22, 0x11, 0x00, 0xdd, 0xcc, 0xbb, 0xaa];
//! let mut ciphertext = [0u8; 8];
//! cipher.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [0x25, 0x87, 0xca, 0xe2, 0x7a, 0x12, 0xd3, 0x00]);
//! # Ok::<(), tc_crypto_engines::SkipjackError>(())
//! ```

mod engine;
mod params;

pub use engine::SkipjackEngine;
pub use params::SkipjackParams;

use core::fmt;

/// SKIPJACK key length in bytes (80 bits).
pub const SKIPJACK_KEY_BYTES: usize = 10;
/// SKIPJACK block length in bytes (64 bits).
pub const SKIPJACK_BLOCK_BYTES: usize = 8;

/// An error from SKIPJACK parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkipjackError {
    /// The key was not exactly 10 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one block.
    BufferTooShort,
}

impl fmt::Display for SkipjackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => {
                write!(f, "SKIPJACK key must be {SKIPJACK_KEY_BYTES} bytes, got {n}")
            }
            Self::NotInitialised => write!(f, "SKIPJACK engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one SKIPJACK block"),
        }
    }
}

impl core::error::Error for SkipjackError {}
