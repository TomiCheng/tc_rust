//! Serpent and Tnepres 128-bit block ciphers, ported from Bouncy Castle's
//! `SerpentEngine`, `TnepresEngine`, and shared `SerpentEngineBase`.
//!
//! Both engines use the same 32-round bitsliced Serpent core. `Tnepres` is the
//! byte/word-reversed representation created from the endianness convention in
//! the original AES-submission vectors; it is not interchangeable with
//! `Serpent` for identical key and block byte strings.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_block_cipher::{SerpentEngine, SerpentParams};
//!
//! let params = SerpentParams::new(&[0u8; 16])?;
//! let mut cipher = SerpentEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 16];
//! cipher.process_block(&[0u8; 16], &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x36, 0x20, 0xb1, 0x7a, 0xe6, 0xa9, 0x93, 0xd0,
//!     0x96, 0x18, 0xb8, 0x76, 0x82, 0x66, 0xba, 0xe9,
//! ]);
//! # Ok::<(), tc_block_cipher::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod cipher;
mod engine;
mod params;

pub use engine::{SerpentEngine, TnepresEngine};
pub use params::SerpentParams;

/// Serpent and Tnepres block length in bytes (128 bits).
pub const SERPENT_BLOCK_BYTES: usize = 16;
/// Minimum supported key length in bytes.
pub const SERPENT_MIN_KEY_BYTES: usize = 4;
/// Maximum supported key length in bytes.
pub const SERPENT_MAX_KEY_BYTES: usize = 32;
/// Key lengths must be a multiple of this many bytes.
pub const SERPENT_KEY_STEP_BYTES: usize = 4;
