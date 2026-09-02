//! AES-128, AES-192, and AES-256 block cipher.
//!
//! [`AesEngine`] uses the portable T-table implementation, and on x86 and
//! x86_64 detects AES-NI when it is constructed and uses that instead where the
//! processor offers it. The `force-portable-aes` feature compiles the
//! accelerated backend out entirely. [`AesLightEngine`] is the small-footprint
//! representation, for callers who want it even where AES-NI is available; both
//! engines compute the same function.
//!
//! ```
//! use tc_aes::{AesEngine, BLOCK_BYTES};
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_params::KeyRef;
//!
//! // FIPS 197 附錄 C 的 AES-128 向量。
//! let key = [
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//! ];
//! let plaintext = [
//!     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//!     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
//! ];
//!
//! let mut engine = AesEngine::new();
//! engine.init(CipherDirection::Encrypt, &KeyRef::new(&key))?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&plaintext, &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
//!     0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
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
mod light_engine;

#[cfg(aes_ni)]
mod x86;

pub use engine::AesEngine;
pub use light_engine::AesLightEngine;

/// AES block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// Accepted key lengths in bytes (128, 192, and 256 bits).
pub const KEY_BYTES: [usize; 3] = [16, 24, 32];
