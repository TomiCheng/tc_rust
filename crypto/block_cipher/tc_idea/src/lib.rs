//! International Data Encryption Algorithm (IDEA).
//!
//! IDEA runs eight identical rounds over four 16-bit words followed by an
//! output transform, mixing addition modulo `2^16`, multiplication modulo
//! `2^16 + 1`, and exclusive-or. Encryption and decryption share the same round
//! function and differ only in the subkey schedule, so the direction is fixed
//! when the engine is initialised.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_idea::{BLOCK_BYTES, IdeaEngine, KEY_BYTES};
//! use tc_params::KeyParams;
//!
//! // `tc_params` 只提供 trait,呼叫端自行決定金鑰怎麼存;這是最小的借用式包裝。
//! struct Key<'a>(&'a [u8]);
//!
//! impl KeyParams for Key<'_> {
//!     fn key(&self) -> &[u8] {
//!         self.0
//!     }
//! }
//!
//! let key: [u8; KEY_BYTES] = [
//!     0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
//!     0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08,
//! ];
//! let plaintext = [0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
//!
//! // 方向在 init 時決定,之後每個區塊都用同一份 subkey schedule。
//! let mut engine = IdeaEngine::new();
//! engine.init(CipherDirection::Encrypt, &Key(&key))?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [0x11, 0xFB, 0xED, 0x2B, 0x01, 0x98, 0x6D, 0xE5]);
//!
//! // 換方向要重新 init;工作金鑰會換成反元素排程。
//! engine.init(CipherDirection::Decrypt, &Key(&key))?;
//!
//! let mut recovered = [0u8; BLOCK_BYTES];
//! engine.process_block(&ciphertext, &mut recovered)?;
//! assert_eq!(recovered, plaintext);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod cipher;
mod engine;

pub use engine::IdeaEngine;

/// IDEA block length in bytes (64 bits).
pub const BLOCK_BYTES: usize = 8;
/// IDEA key length in bytes (128 bits).
pub const KEY_BYTES: usize = 16;
