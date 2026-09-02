//! Twofish block cipher.
//!
//! Twofish takes a 128-, 192-, or 256-bit key over a 128-bit block. Key setup
//! derives forty subkeys and four key-dependent S-box tables; block processing
//! is then sixteen rounds between input and output whitening.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_params::KeyRef;
//! use tc_twofish::{BLOCK_BYTES, TwofishEngine};
//!
//! let key = [0u8; 16];
//! let plaintext = [0u8; BLOCK_BYTES];
//!
//! let mut engine = TwofishEngine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x9f, 0x58, 0x9f, 0x5c, 0xf6, 0x12, 0x2c, 0x32,
//!     0xb6, 0xbf, 0xec, 0x2f, 0x2a, 0xe8, 0xc3, 0x5a,
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

pub use engine::TwofishEngine;

/// Twofish block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// Accepted key lengths in bytes (128, 192, and 256 bits).
pub const KEY_BYTES: [usize; 3] = [16, 24, 32];
