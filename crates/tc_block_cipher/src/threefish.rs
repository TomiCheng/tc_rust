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
//! use tc_block_cipher::{ThreefishEngine, ThreefishParams};
//!
//! // Threefish-256: a 32-byte key and an optional 16-byte tweak.
//! let key = [0x42u8; 32];
//! let params = ThreefishParams::new(&key, None)?;
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
//! # Ok::<(), tc_block_cipher::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod cipher;
mod engine;
mod params;

pub use engine::ThreefishEngine;
pub use params::ThreefishParams;

/// The fixed tweak length, in bytes (128 bit), shared by all block sizes.
pub const TWEAK_BYTES: usize = 16;
