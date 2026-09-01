//! ChaCha stream ciphers.
//!
//! The crate provides original ChaCha, IETF ChaCha7539, and XChaCha20.
//!
//! ```
//! use tc_chacha::{ChaChaEngine, IV_BYTES};
//! use tc_cipher::{CipherDirection, StreamCipher, StreamCipherInit};
//! use tc_params::KeyWithIvRef;
//!
//! let key = [0u8; 32];
//! let iv = [0u8; IV_BYTES];
//! let mut cipher = ChaChaEngine::new();
//! cipher.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &iv))?;
//!
//! let mut output = [0u8; 64];
//! cipher.process_bytes(&[0u8; 64], &mut output)?;
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod chacha;
pub mod chacha7539;
mod engine;
pub mod xchacha20;

pub use chacha7539::ChaCha7539Engine;
pub use engine::ChaChaEngine;
pub use xchacha20::XChaCha20Engine;

/// Default ChaCha round count.
pub const DEFAULT_ROUNDS: usize = 20;
/// ChaCha keystream-block length in bytes.
pub const BLOCK_BYTES: usize = 64;
/// Original ChaCha IV length in bytes.
pub const IV_BYTES: usize = 8;
/// Supported key lengths in bytes.
pub const KEY_BYTES: [usize; 2] = [16, 32];

const MAX_ROUNDS: usize = i32::MAX as usize - 1;
