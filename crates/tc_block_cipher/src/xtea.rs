//! XTEA (eXtended TEA) 64-bit block cipher, ported from Bouncy Castle's
//! `XteaEngine`.
//!
//! XTEA fixes TEA's key-schedule weaknesses by interleaving the key words
//! differently each round. This port precomputes the two 32-word round-key
//! schedules (`sum0`/`sum1`) at [`init`](tc_cipher_core::BlockCipherInit::init).
//!
//! ```
//! use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_block_cipher::{XteaEngine, XteaParams};
//!
//! let key = [0u8; 16];
//! let params = XteaParams::new(&key)?;
//! let mut cipher = XteaEngine::new();
//! cipher.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut ciphertext = [0u8; 8];
//! cipher.process_block(&[0u8; 8], &mut ciphertext)?;
//! assert_eq!(ciphertext, [0xde, 0xe9, 0xd4, 0xd8, 0xf7, 0x13, 0x1e, 0xd9]);
//! # Ok::<(), tc_block_cipher::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod engine;
mod params;

pub use engine::XteaEngine;
pub use params::XteaParams;

/// XTEA key length in bytes (128 bits).
pub const XTEA_KEY_BYTES: usize = 16;
/// XTEA block length in bytes (64 bits).
pub const XTEA_BLOCK_BYTES: usize = 8;
