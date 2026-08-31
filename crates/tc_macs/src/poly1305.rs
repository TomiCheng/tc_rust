//! Poly1305 message authentication code.
//!
//! # Poly1305 with AES
//!
//! ```rust
//! use tc_block_cipher::{AesEngine, AesParams};
//! use tc_crypto_core::{Mac, MacInit};
//! use tc_macs::poly1305::{
//!     CipherEngine, CipherParams, KEY_BYTES, NONCE_BYTES, TAG_BYTES,
//! };
//!
//! let key = [0x11; KEY_BYTES];
//! let nonce = [0x22; NONCE_BYTES];
//! let params =
//!     CipherParams::try_new(&key, &nonce, |cipher_key| AesParams::new(cipher_key)).unwrap();
//!
//! let mut mac = CipherEngine::new(AesEngine::new()).unwrap();
//! mac.init(&params).unwrap();
//! mac.update(b"message").unwrap();
//!
//! let mut tag = [0_u8; TAG_BYTES];
//! let written = mac.do_final(&mut tag).unwrap();
//! assert_eq!(written, TAG_BYTES);
//! ```

mod engine;
mod params;

pub use engine::{CipherEngine, CipherError, Engine, Error};
pub use params::{BorrowedParams, CipherParams};

/// Poly1305 input block length in bytes.
pub const BLOCK_BYTES: usize = 16;

/// Key length required by Poly1305's optional block cipher.
pub const CIPHER_KEY_BYTES: usize = 16;

/// Poly1305 one-time key length in bytes.
pub const KEY_BYTES: usize = 32;

/// Nonce length required by Poly1305's optional block-cipher form.
pub const NONCE_BYTES: usize = 16;

/// Poly1305 authentication-tag length in bytes.
pub const TAG_BYTES: usize = 16;
