//! Threefish tweakable block cipher, ported from Bouncy Castle's
//! `ThreefishEngine` (Skein 1.3 / NIST SHA-3 submission).
//!
//! Threefish comes in three block sizes — 256, 512 and 1024 bits — where the key
//! is always the same size as the block, plus a fixed 128-bit tweak. Build a
//! validated [`ThreefishParams`], then [`init`](tc_crypto_core::BlockCipher::init)
//! a [`ThreefishEngine`] for encryption or decryption and transform one block at
//! a time with [`process_block`](tc_crypto_core::BlockCipher::process_block).
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{ThreefishBlockSize, ThreefishEngine, ThreefishParams};
//!
//! // Threefish-256: a 32-byte key and an optional 16-byte tweak.
//! let key = [0x42u8; 32];
//! let params = ThreefishParams::new(ThreefishBlockSize::B256, &key, None)?;
//!
//! let mut cipher = ThreefishEngine::new();
//! cipher.init(true, &params)?; // true = encrypt
//!
//! let plaintext = *b"one 32-byte Threefish block !!!!";
//! let mut ciphertext = [0u8; 32];
//! cipher.process_block(&plaintext, &mut ciphertext)?;
//!
//! // Re-init for decryption and recover the plaintext.
//! cipher.init(false, &params)?; // false = decrypt
//! let mut recovered = [0u8; 32];
//! cipher.process_block(&ciphertext, &mut recovered)?;
//! assert_eq!(recovered, plaintext);
//! # Ok::<(), tc_crypto_engines::ThreefishError>(())
//! ```

mod cipher;
mod engine;
mod params;

pub use engine::ThreefishEngine;
pub use params::ThreefishParams;

use core::fmt;

/// The fixed tweak length, in bytes (128 bit), shared by all block sizes.
pub const TWEAK_BYTES: usize = 16;

/// The block size of a Threefish instance (bc's 256 / 512 / 1024 bit variants).
///
/// An enum rather than a raw bit count so that an unsupported size simply cannot
/// be expressed: [`ThreefishEngine::new`] takes one of these and therefore never
/// has to reject or panic on a bad block size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreefishBlockSize {
    /// Threefish-256 (32-byte block and key).
    B256,
    /// Threefish-512 (64-byte block and key).
    B512,
    /// Threefish-1024 (128-byte block and key).
    B1024,
}

impl ThreefishBlockSize {
    /// The block size in bytes (32 / 64 / 128) — also the required key length.
    pub const fn bytes(self) -> usize {
        match self {
            ThreefishBlockSize::B256 => 32,
            ThreefishBlockSize::B512 => 64,
            ThreefishBlockSize::B1024 => 128,
        }
    }
}

/// An error from the Threefish cipher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreefishError {
    /// The key length (bytes) is not a legal Threefish key size (32 / 64 / 128).
    InvalidKeyLength(usize),
    /// The tweak length (bytes) is not 16.
    InvalidTweakLength(usize),
    /// `process_block` was called before a successful `init`.
    NotInitialised,
    /// An input or output buffer was shorter than one block.
    BufferTooShort,
}

impl fmt::Display for ThreefishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreefishError::InvalidKeyLength(n) => write!(
                f,
                "Threefish key must be 32, 64 or 128 bytes, got {n}"
            ),
            ThreefishError::InvalidTweakLength(n) => {
                write!(f, "Threefish tweak must be {TWEAK_BYTES} bytes, got {n}")
            }
            ThreefishError::NotInitialised => write!(f, "Threefish engine not initialised"),
            ThreefishError::BufferTooShort => write!(f, "buffer too short for one block"),
        }
    }
}

impl core::error::Error for ThreefishError {}
