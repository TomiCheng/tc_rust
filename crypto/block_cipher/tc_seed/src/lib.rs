//! SEED block cipher (RFC 4009).
//!
//! SEED is a sixteen-round Feistel cipher with a 128-bit key and a 128-bit
//! block, working on two 64-bit halves. The round function and the key schedule
//! both run on four 256-entry S-box tables. Both directions share one working
//! key and differ only in the order the rounds are applied.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_params::KeyRef;
//! use tc_seed::{BLOCK_BYTES, KEY_BYTES, SeedEngine};
//!
//! let key = [0u8; KEY_BYTES];
//! let plaintext = [
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//! ];
//!
//! let mut engine = SeedEngine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x5E, 0xBA, 0xC6, 0xE0, 0x05, 0x4E, 0x16, 0x68,
//!     0x19, 0xAF, 0xF1, 0xCC, 0x6D, 0x34, 0x6C, 0xDB,
//! ]);
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

pub use engine::SeedEngine;

/// SEED block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// SEED key length in bytes (128 bits).
pub const KEY_BYTES: usize = 16;
