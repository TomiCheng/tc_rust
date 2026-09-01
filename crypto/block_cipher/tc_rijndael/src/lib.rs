//! Generalized Rijndael block cipher.
//!
//! Unlike AES, generalized Rijndael supports 128-, 160-, 192-, 224-, and
//! 256-bit blocks and keys in any combination. The block size is fixed by the
//! Engine type; the key size is selected when the Engine is initialized.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_params::KeyRef;
//! use tc_rijndael::Rijndael128Engine;
//!
//! let key = [
//!     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//! let mut engine = Rijndael128Engine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut ciphertext = [0u8; 16];
//! engine.process_block(&[0u8; 16], &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x0e, 0xdd, 0x33, 0xd3, 0xc6, 0x21, 0xe5, 0x46,
//!     0x45, 0x5b, 0xd8, 0xba, 0x14, 0x18, 0xbe, 0xc8,
//! ]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod engine;
mod tables;

pub use engine::RijndaelEngine;

/// Rijndael engine with a 128-bit block.
pub type Rijndael128Engine = RijndaelEngine<4>;
/// Rijndael engine with a 160-bit block.
pub type Rijndael160Engine = RijndaelEngine<5>;
/// Rijndael engine with a 192-bit block.
pub type Rijndael192Engine = RijndaelEngine<6>;
/// Rijndael engine with a 224-bit block.
pub type Rijndael224Engine = RijndaelEngine<7>;
/// Rijndael engine with a 256-bit block.
pub type Rijndael256Engine = RijndaelEngine<8>;

/// Supported block lengths in bits.
pub const BLOCK_BITS: [usize; 5] = [128, 160, 192, 224, 256];
/// Supported key lengths in bytes.
pub const KEY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];

pub(crate) const fn valid_block_columns(columns: usize) -> bool {
    columns >= 4 && columns <= 8
}
