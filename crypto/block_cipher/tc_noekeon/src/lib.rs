//! Noekeon block cipher, in direct-key mode.
//!
//! Noekeon processes a 128-bit block as four big-endian 32-bit words over
//! sixteen rounds of `theta`, `pi1`, `gamma`, `pi2`, followed by an output
//! transform. Encryption and decryption share those primitives and differ only
//! in the order they are applied; in direct-key mode there is no key schedule,
//! so the decryption working key is just the key with one zero-key `theta`
//! applied.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_noekeon::{BLOCK_BYTES, KEY_BYTES, NoekeonEngine};
//! use tc_params::KeyRef;
//!
//! let key = [0u8; KEY_BYTES];
//! let plaintext = [0u8; BLOCK_BYTES];
//!
//! // 方向在 init 時決定,解密時工作金鑰會先過一次零金鑰 theta。
//! let mut engine = NoekeonEngine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0xB1, 0x65, 0x68, 0x51, 0x69, 0x9E, 0x29, 0xFA,
//!     0x24, 0xB7, 0x01, 0x48, 0x50, 0x3D, 0x2D, 0xFC,
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

pub use engine::NoekeonEngine;

/// Noekeon block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// Noekeon key length in bytes (128 bits).
pub const KEY_BYTES: usize = 16;
