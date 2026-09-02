//! Threefish tweakable block cipher.
//!
//! Threefish has 256-, 512-, and 1024-bit variants. In each variant the key is
//! exactly one block long and the optional tweak is 128 bits. An absent tweak
//! is equivalent to sixteen zero bytes.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_threefish::{Params, Threefish256Engine};
//!
//! let key = [0u8; 32];
//! let plaintext = [0u8; 32];
//! let mut engine = Threefish256Engine::new();
//! engine.init(CipherDirection::Encrypt, &Params::new(&key))?;
//!
//! let mut ciphertext = [0u8; 32];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(
//!     ciphertext,
//!     [
//!         0x84, 0xda, 0x2a, 0x1f, 0x8b, 0xea, 0xee, 0x94,
//!         0x70, 0x66, 0xae, 0x3e, 0x31, 0x03, 0xf1, 0xad,
//!         0x53, 0x6d, 0xb1, 0xf4, 0xa1, 0x19, 0x24, 0x95,
//!         0x11, 0x6b, 0x9f, 0x3c, 0xe6, 0x13, 0x3f, 0xd8,
//!     ]
//! );
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod cipher;
mod engine;
mod params;

pub use engine::ThreefishEngine;
pub use params::Params;
pub use tc_params::TweakParams;

/// Threefish-256 engine with a 32-byte block and key.
pub type Threefish256Engine = ThreefishEngine<4>;
/// Threefish-512 engine with a 64-byte block and key.
pub type Threefish512Engine = ThreefishEngine<8>;
/// Threefish-1024 engine with a 128-byte block and key.
pub type Threefish1024Engine = ThreefishEngine<16>;

/// Fixed tweak length shared by all Threefish variants.
pub const TWEAK_BYTES: usize = 16;

pub(crate) const fn valid_word_count(words: usize) -> bool {
    matches!(words, 4 | 8 | 16)
}
