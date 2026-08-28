//! RC5 block cipher (RFC 2040), ported from Bouncy Castle's `RC532Engine` and
//! `RC564Engine`.
//!
//! RC5 is parameterised by word size, round count, and key length. Bouncy Castle
//! ships two fixed word sizes; this port expresses the shared algorithm over an
//! [`Rc5Word`](engine::Rc5Word) trait and exposes them as [`Rc532Engine`]
//! (32-bit words, 64-bit block) and [`Rc564Engine`] (64-bit words, 128-bit
//! block). [`Rc5Params::new`] uses the standard twelve rounds;
//! [`Rc5Params::with_rounds`] sets a different count.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{Rc532Engine, Rc5Params};
//!
//! // RFC 2040 exercises RC5 in CBC mode; a single block with a zero IV is ECB.
//! let params = Rc5Params::with_rounds(&[0x00], 2)?;
//! let mut cipher = Rc532Engine::new();
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 8];
//! cipher.process_block(&[0u8; 8], &mut ciphertext)?;
//! assert_eq!(ciphertext, [0xdc, 0xa2, 0x69, 0x4b, 0xf4, 0x0e, 0x07, 0x88]);
//! # Ok::<(), tc_crypto_engines::Rc5Error>(())
//! ```

mod engine;
mod params;

pub use engine::{Rc532Engine, Rc564Engine, Rc5Word};
pub use params::Rc5Params;

use core::fmt;

/// The standard RC5 round count.
pub const RC5_DEFAULT_ROUNDS: usize = 12;
/// The maximum RC5 round count.
pub const RC5_MAX_ROUNDS: usize = 255;
/// The maximum RC5 key length in bytes.
pub const RC5_MAX_KEY_BYTES: usize = 255;
/// RC5-32 block length in bytes (two 32-bit words).
pub const RC5_32_BLOCK_BYTES: usize = 8;
/// RC5-64 block length in bytes (two 64-bit words).
pub const RC5_64_BLOCK_BYTES: usize = 16;

/// An error from RC5 parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rc5Error {
    /// The key was empty or longer than 255 bytes.
    InvalidKeyLength(usize),
    /// The round count was greater than 255.
    InvalidRounds(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one block.
    BufferTooShort,
}

impl fmt::Display for Rc5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => write!(
                f,
                "RC5 key must be 1..={RC5_MAX_KEY_BYTES} bytes, got {n}"
            ),
            Self::InvalidRounds(n) => {
                write!(f, "RC5 round count must be 0..={RC5_MAX_ROUNDS}, got {n}")
            }
            Self::NotInitialised => write!(f, "RC5 engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one RC5 block"),
        }
    }
}

impl core::error::Error for Rc5Error {}
