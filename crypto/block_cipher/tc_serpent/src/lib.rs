//! Serpent and Tnepres block ciphers.
//!
//! Both engines run the same thirty-two-round bitsliced core over a 128-bit
//! block, with keys of 4 to 32 bytes in four-byte steps. [`TnepresEngine`] is
//! the byte- and word-reversed representation that comes from the endianness
//! convention of the original AES-submission vectors; it is a different cipher
//! as far as any given byte string is concerned, not an alias.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_params::KeyRef;
//! use tc_serpent::{BLOCK_BYTES, SerpentEngine};
//!
//! let key = [0u8; 16];
//! let plaintext = [0u8; BLOCK_BYTES];
//!
//! let mut engine = SerpentEngine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x36, 0x20, 0xb1, 0x7a, 0xe6, 0xa9, 0x93, 0xd0,
//!     0x96, 0x18, 0xb8, 0x76, 0x82, 0x66, 0xba, 0xe9,
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

pub use engine::{SerpentEngine, TnepresEngine};

/// Serpent and Tnepres block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// Minimum key length in bytes.
pub const MIN_KEY_BYTES: usize = 4;
/// Maximum key length in bytes.
pub const MAX_KEY_BYTES: usize = 32;
/// Key lengths must be a multiple of this many bytes.
pub const KEY_STEP_BYTES: usize = 4;
