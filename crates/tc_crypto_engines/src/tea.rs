//! TEA (Tiny Encryption Algorithm) 64-bit block cipher, ported from Bouncy
//! Castle's `TeaEngine`.
//!
//! TEA uses a 128-bit key and a 64-bit block over 32 rounds, driven by the
//! golden-ratio constant `delta`. The two 32-bit words are big-endian.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{TeaEngine, TeaParams};
//!
//! let key = [0u8; 16];
//! let params = TeaParams::new(&key)?;
//! let mut cipher = TeaEngine::new();
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 8];
//! cipher.process_block(&[0u8; 8], &mut ciphertext)?;
//! assert_eq!(ciphertext, [0x41, 0xea, 0x3a, 0x0a, 0x94, 0xba, 0xa9, 0x40]);
//! # Ok::<(), tc_crypto_engines::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod engine;
mod params;

pub use engine::TeaEngine;
pub use params::TeaParams;

/// TEA key length in bytes (128 bits).
pub const TEA_KEY_BYTES: usize = 16;
/// TEA block length in bytes (64 bits).
pub const TEA_BLOCK_BYTES: usize = 8;
