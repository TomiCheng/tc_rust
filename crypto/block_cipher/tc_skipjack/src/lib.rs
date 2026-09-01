//! SKIPJACK block cipher.
//!
//! SKIPJACK has an 80-bit key and a 64-bit block, run over thirty-two steps
//! that alternate two rules in runs of eight. Both rules are built from the
//! keyed `G` permutation, itself four rounds of a single byte-substitution
//! table. Decryption applies `G`'s inverse with the step counter reversed.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_params::KeyRef;
//! use tc_skipjack::{BLOCK_BYTES, SkipjackEngine};
//!
//! let key = [0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
//! let plaintext = [0x33, 0x22, 0x11, 0x00, 0xdd, 0xcc, 0xbb, 0xaa];
//!
//! let mut engine = SkipjackEngine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [0x25, 0x87, 0xca, 0xe2, 0x7a, 0x12, 0xd3, 0x00]);
//!
//! engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
//!
//! let mut recovered = [0u8; BLOCK_BYTES];
//! engine.process_block(&ciphertext, &mut recovered)?;
//! assert_eq!(recovered, plaintext);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod cipher;
mod engine;

pub use engine::SkipjackEngine;

/// SKIPJACK block length in bytes (64 bits).
pub const BLOCK_BYTES: usize = 8;
/// SKIPJACK key length in bytes (80 bits).
pub const KEY_BYTES: usize = 10;
