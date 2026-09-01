//! RC6-32/20 block cipher.
//!
//! RC6 operates on four 32-bit words for twenty rounds. It accepts a
//! variable-length key and expands it into forty-four working words.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_params::KeyRef;
//! use tc_rc6::{BLOCK_BYTES, Rc6Engine};
//!
//! let key = [0u8; 16];
//! let plaintext = [
//!     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let mut engine = Rc6Engine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0xf7, 0x1f, 0x65, 0xe7, 0xb8, 0x0c, 0x0c, 0x69,
//!     0x66, 0xfe, 0xe6, 0x07, 0x98, 0x4b, 0x5c, 0xdf,
//! ]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod cipher;
mod engine;

pub use engine::Rc6Engine;

/// RC6 block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// Fixed round count for RC6-32/20.
pub const ROUNDS: usize = 20;
/// Maximum RC6 key length in bytes.
pub const MAX_KEY_BYTES: usize = 255;
