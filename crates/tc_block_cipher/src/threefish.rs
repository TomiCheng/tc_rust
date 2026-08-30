//! Threefish tweakable block cipher, ported from Bouncy Castle's
//! `ThreefishEngine` (Skein 1.3 / NIST SHA-3 submission).
//!
//! Threefish comes in three block sizes — 256, 512 and 1024 bits — where the key
//! is always the same size as the block, plus a fixed 128-bit tweak. Build a
//! validated [`ThreefishParams`], then [`init`](tc_cipher_core::BlockCipherInit::init)
//! a [`ThreefishEngine`] for encryption or decryption and transform one block at
//! a time with [`process_block`](tc_cipher_core::BlockCipher::process_block).
//!
//! ```
//! use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_block_cipher::{Threefish256Engine, Threefish256Params};
//!
//! // Threefish-256: a 32-byte key and an optional 16-byte tweak.
//! let key = [0x42u8; 32];
//! let params = Threefish256Params::new(&key, None)?;
//!
//! let mut cipher = Threefish256Engine::new();
//! cipher.init(CipherDirection::Encrypt, &params)?;
//!
//! let plaintext = *b"one 32-byte Threefish block !!!!";
//! let mut ciphertext = [0u8; 32];
//! cipher.process_block(&plaintext, &mut ciphertext)?;
//!
//! // Re-init for decryption and recover the plaintext.
//! cipher.init(CipherDirection::Decrypt, &params)?;
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

/// Threefish-256 engine with four 64-bit words per block.
pub type Threefish256Engine = ThreefishEngine<4>;
/// Threefish-512 engine with eight 64-bit words per block.
pub type Threefish512Engine = ThreefishEngine<8>;
/// Threefish-1024 engine with sixteen 64-bit words per block.
pub type Threefish1024Engine = ThreefishEngine<16>;

/// Parameters containing exactly one Threefish-256 key and tweak.
pub type Threefish256Params = ThreefishParams<4>;
/// Parameters containing exactly one Threefish-512 key and tweak.
pub type Threefish512Params = ThreefishParams<8>;
/// Parameters containing exactly one Threefish-1024 key and tweak.
pub type Threefish1024Params = ThreefishParams<16>;

/// The fixed tweak length, in bytes (128 bit), shared by all block sizes.
pub const TWEAK_BYTES: usize = 16;

pub(crate) const fn valid_word_count(words: usize) -> bool {
    matches!(words, 4 | 8 | 16)
}
