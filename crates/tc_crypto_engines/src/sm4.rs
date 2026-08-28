//! SM4 128-bit block cipher (GM/T 0002-2012), ported from Bouncy Castle's
//! `SM4Engine`.
//!
//! SM4 has a 128-bit key and 128-bit block, processed as four big-endian 32-bit
//! words over 32 rounds. Encryption and decryption share the same round loop;
//! the direction is baked into the round-key schedule at
//! [`init`](tc_crypto_core::BlockCipher::init) (the decryption keys are the
//! encryption keys in reverse).
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{Sm4Engine, Sm4Params};
//!
//! let key = [
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
//! ];
//! let params = Sm4Params::new(&key)?;
//! let mut cipher = Sm4Engine::new();
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 16];
//! cipher.process_block(&key, &mut ciphertext)?; // plaintext == key here
//! assert_eq!(ciphertext, [
//!     0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
//!     0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
//! ]);
//! # Ok::<(), tc_crypto_engines::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod engine;
mod params;

pub use engine::Sm4Engine;
pub use params::Sm4Params;

/// SM4 key length in bytes (128 bits).
pub const SM4_KEY_BYTES: usize = 16;
/// SM4 block length in bytes (128 bits).
pub const SM4_BLOCK_BYTES: usize = 16;
