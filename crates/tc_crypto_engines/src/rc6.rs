//! RC6 128-bit block cipher, ported from Bouncy Castle's `RC6Engine`.
//!
//! RC6 is the AES-submission RC6-32/20/b: four 32-bit words, twenty rounds, and a
//! variable-length key. It shares RC5's three-phase key schedule but adds a
//! quadratic mixing function `f(x) = x(2x + 1)` and a four-register round.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{Rc6Engine, Rc6Params};
//!
//! let key = [0u8; 16];
//! let params = Rc6Params::new(&key)?;
//! let mut cipher = Rc6Engine::new();
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 16];
//! let plaintext = [
//!     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//! cipher.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0xf7, 0x1f, 0x65, 0xe7, 0xb8, 0x0c, 0x0c, 0x69,
//!     0x66, 0xfe, 0xe6, 0x07, 0x98, 0x4b, 0x5c, 0xdf,
//! ]);
//! # Ok::<(), tc_crypto_engines::Rc6Error>(())
//! ```

mod engine;
mod params;

pub use engine::Rc6Engine;
pub use params::Rc6Params;

use core::fmt;

/// RC6 block length in bytes (four 32-bit words).
pub const RC6_BLOCK_BYTES: usize = 16;
/// The fixed RC6 round count.
pub const RC6_ROUNDS: usize = 20;
/// The maximum RC6 key length in bytes.
pub const RC6_MAX_KEY_BYTES: usize = 255;

/// An error from RC6 parameter validation or block processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rc6Error {
    /// The key was empty or longer than 255 bytes.
    InvalidKeyLength(usize),
    /// `process_block` was called before successful initialization.
    NotInitialised,
    /// An input or output buffer was shorter than one block.
    BufferTooShort,
}

impl fmt::Display for Rc6Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => write!(
                f,
                "RC6 key must be 1..={RC6_MAX_KEY_BYTES} bytes, got {n}"
            ),
            Self::NotInitialised => write!(f, "RC6 engine not initialised"),
            Self::BufferTooShort => write!(f, "buffer too short for one RC6 block"),
        }
    }
}

impl core::error::Error for Rc6Error {}
