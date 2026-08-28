//! Noekeon 128-bit block cipher (direct-key mode), ported from Bouncy Castle's
//! `NoekeonEngine`.
//!
//! Noekeon has a 128-bit key and a 128-bit block, processed as four big-endian
//! 32-bit words over sixteen rounds. Encryption and decryption share the same
//! `theta`/`pi1`/`gamma`/`pi2` primitives; decryption simply runs the rounds in
//! reverse over a key that [`init`](tc_crypto_core::BlockCipher::init) pre-mixes
//! with a single zero-key `theta`.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{NoekeonEngine, NoekeonParams};
//!
//! let key = [0u8; 16];
//! let params = NoekeonParams::new(&key)?;
//! let mut cipher = NoekeonEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 16];
//! cipher.process_block(&[0u8; 16], &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0xB1, 0x65, 0x68, 0x51, 0x69, 0x9E, 0x29, 0xFA,
//!     0x24, 0xB7, 0x01, 0x48, 0x50, 0x3D, 0x2D, 0xFC,
//! ]);
//! # Ok::<(), tc_crypto_engines::NoekeonError>(())
//! ```

mod engine;
mod params;

pub use engine::NoekeonEngine;
pub use params::NoekeonParams;

use core::fmt;

/// Noekeon key length in bytes (128 bits).
pub const NOEKEON_KEY_BYTES: usize = 16;
/// Noekeon block length in bytes (128 bits).
pub const NOEKEON_BLOCK_BYTES: usize = 16;

/// An error from Noekeon parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoekeonError {
    /// The key was not exactly 16 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one block.
    BufferTooShort,
}

impl fmt::Display for NoekeonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => {
                write!(f, "Noekeon key must be {NOEKEON_KEY_BYTES} bytes, got {n}")
            }
            Self::NotInitialised => write!(f, "Noekeon engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one Noekeon block"),
        }
    }
}

impl core::error::Error for NoekeonError {}
