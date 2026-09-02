//! SM4 block cipher (GM/T 0002-2012).
//!
//! SM4 runs thirty-two rounds over four big-endian 32-bit words, with a 128-bit
//! key and a 128-bit block. Both directions share the same round loop and
//! differ only in the order of the round keys, so the direction is fixed when
//! the engine is initialised.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_params::KeyRef;
//! use tc_sm4::{BLOCK_BYTES, Sm4Engine};
//!
//! let key = [
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
//! ];
//! let plaintext = key; // 這組公開向量的明文剛好等於金鑰
//!
//! let mut engine = Sm4Engine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
//!     0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
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

pub use engine::Sm4Engine;

/// SM4 block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// SM4 key length in bytes (128 bits).
pub const KEY_BYTES: usize = 16;
