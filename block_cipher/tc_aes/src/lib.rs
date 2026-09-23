//! AES-128, AES-192 and AES-256 single-block encryption and decryption.
//!
//! Import [`BlockCipherInit`](tc_block_cipher::BlockCipherInit) to install a key
//! and [`BlockCipher`](tc_block_cipher::BlockCipher) to process a block.
//! Keys must contain 16, 24 or 32 bytes; the block size is always 16 bytes.
//!
//! # Choosing an engine
//!
//! [`AesEngine`] chooses a backend for you. Enable the `rustcrypto` Cargo
//! feature for a constant-time backend even without AES-NI. Without that feature
//! it uses AES-NI when available, otherwise the variable-time [`AesTableEngine`].
//!
//! For explicit selection, `AesX86Engine` is available on x86/x86-64 and
//! `AesRustCryptoEngine` with the `rustcrypto` feature. [`AesTableEngine`]
//! and [`AesLightEngine`] are portable but use secret-dependent lookups;
//! neither is suitable when cache-timing attacks are in scope.
//!
//! # Encrypting and decrypting one block
//!
//! This example uses the AES-128 known-answer vector from FIPS 197.
//!
//! ```
//! use tc_aes::{AesEngine, ALGO_NAME, BLOCK_BYTES};
//! use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
//!
//! let key: [u8; 16] = core::array::from_fn(|i| i as u8);
//! let plaintext: [u8; 16] = core::array::from_fn(|i| (i as u8) * 0x11);
//! let mut engine = AesEngine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//! let mut ciphertext = [0; BLOCK_BYTES];
//! assert_eq!(engine.process_block(&plaintext, &mut ciphertext)?, BLOCK_BYTES);
//! assert_eq!(ciphertext, [
//!     0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
//!     0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
//! ]);
//! engine.init(CipherDirection::Decrypt, &KeyRef::new(&key))?;
//! let mut recovered = [0; BLOCK_BYTES];
//! engine.process_block(&ciphertext, &mut recovered)?;
//! assert_eq!(recovered, plaintext);
//! assert_eq!(engine.to_string(), ALGO_NAME);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Buffer and key handling
//!
//! Processing before initialization returns `BlockError::NotInitialised`.
//! Buffers shorter than 16 bytes return `BlockError::BufferTooShort`; longer
//! buffers process only their first block, leaving the output tail intact.
//! An invalid key length returns `InitError::InvalidKeyLength` and preserves
//! the previous key and direction. Engines retain an expanded key rather than
//! borrowing the input key; callers remain responsible for their key buffers.
//! Stored key schedules are wiped on drop, not caller buffers or every temporary.
//!
//! This is a block-cipher primitive, not a message-encryption format. It supplies
//! no padding, nonce management, mode of operation or authentication. Do not
//! encrypt a message by independently encrypting each block; use an appropriate
//! authenticated-encryption construction.
//!
#![no_std]

mod common;
mod engine;
mod light_engine;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod table_engine;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_engine;

pub use engine::AesEngine;
pub use light_engine::AesLightEngine;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::AesRustCryptoEngine;
pub use table_engine::AesTableEngine;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86_engine::AesX86Engine;

/// Algorithm name returned by every engine's `Display` implementation.
///
/// This identifies AES, not the selected backend, key size or direction.
pub const ALGO_NAME: &str = "AES";
/// AES block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// Accepted key lengths in bytes (128, 192, and 256 bits).
pub const KEY_BYTES: [usize; 3] = [16, 24, 32];
