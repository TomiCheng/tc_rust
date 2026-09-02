//! Grain-128AEAD authenticated encryption.
//!
//! `Engine` uses a growable AAD buffer and is available with the default
//! `alloc` feature. [`FixedEngine`] stores at most a caller-selected number of
//! AAD bytes in the engine itself and remains available without `alloc`.
//!
//! # Example
//!
//! ```
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//! use tc_grain128_aead::{Engine, KEY_BYTES, NONCE_BYTES, Params, TAG_BYTES};
//!
//! let key = core::array::from_fn::<_, KEY_BYTES, _>(|i| i as u8);
//! let nonce = core::array::from_fn::<_, NONCE_BYTES, _>(|i| i as u8);
//! let aad = core::array::from_fn::<_, 16, _>(|i| i as u8);
//! let plaintext = core::array::from_fn::<_, 16, _>(|i| i as u8);
//! let params = Params::new(&key, &nonce, &[]);
//!
//! let mut cipher = Engine::new();
//! cipher.init(CipherDirection::Encrypt, &params)?;
//! cipher.process_aad_bytes(&aad)?;
//!
//! let mut output = [0_u8; 16 + TAG_BYTES];
//! let mut written = cipher.process_bytes(&plaintext, &mut output)?;
//! written += cipher.do_final(&mut output[written..])?;
//!
//! assert_eq!(written, output.len());
//! assert_eq!(
//!     output,
//!     [
//!         0x80, 0xB5, 0x3B, 0xE2, 0x8E, 0x93, 0x8B, 0xAE,
//!         0x76, 0xB6, 0x4C, 0xCD, 0x53, 0xBE, 0x4D, 0xE5,
//!         0xFB, 0x07, 0x20, 0xDE, 0x18, 0xEA, 0x8F, 0xAE,
//!     ],
//! );
//!
//! let mut decipher = Engine::new();
//! decipher.init(CipherDirection::Decrypt, &params)?;
//! decipher.process_aad_bytes(&aad)?;
//!
//! let mut recovered = [0_u8; 16];
//! let mut recovered_len = decipher.process_bytes(&output, &mut recovered)?;
//! recovered_len += decipher.do_final(&mut recovered[recovered_len..])?;
//!
//! assert_eq!(recovered_len, plaintext.len());
//! assert_eq!(recovered, plaintext);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod engine;
mod params;

#[cfg(feature = "alloc")]
pub use engine::Engine;
pub use engine::FixedEngine;
pub use params::Params;

/// Secret-key length in bytes.
pub const KEY_BYTES: usize = 16;
/// Nonce length in bytes.
pub const NONCE_BYTES: usize = 12;
/// Authentication-tag length in bytes.
pub const TAG_BYTES: usize = 8;
