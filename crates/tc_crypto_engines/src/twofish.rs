//! Twofish 128-bit block cipher, ported from Bouncy Castle's `TwofishEngine`.
//!
//! Twofish accepts 128-, 192-, and 256-bit keys. Key setup expands forty
//! subkeys and four key-dependent S-box tables; block processing then performs
//! sixteen rounds with input and output whitening.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{TwofishEngine, TwofishParams};
//!
//! let key = [0u8; 16];
//! let params = TwofishParams::new(&key)?;
//! let mut cipher = TwofishEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 16];
//! cipher.process_block(&[0u8; 16], &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x9f, 0x58, 0x9f, 0x5c, 0xf6, 0x12, 0x2c, 0x32,
//!     0xb6, 0xbf, 0xec, 0x2f, 0x2a, 0xe8, 0xc3, 0x5a,
//! ]);
//! # Ok::<(), tc_crypto_engines::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod engine;
mod params;

pub use engine::TwofishEngine;
pub use params::TwofishParams;

/// Twofish block length in bytes (128 bits).
pub const TWOFISH_BLOCK_BYTES: usize = 16;
/// Valid Twofish key lengths in bytes (128, 192, and 256 bits).
pub const TWOFISH_KEY_BYTES: [usize; 3] = [16, 24, 32];
