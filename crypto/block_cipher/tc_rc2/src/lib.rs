//! RC2 block cipher (RFC 2268).
//!
//! RC2 has a variable-length key whose effective strength can be selected
//! independently of the supplied key bytes. [`Params::new`] uses the key's full
//! length, while [`Params::with_effective_key_bits`] selects it explicitly.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_rc2::{BLOCK_BYTES, Params, Rc2Engine};
//!
//! let key = [0xff_u8; 8];
//! let params = Params::new(&key);
//! let mut engine = Rc2Engine::new();
//! engine.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut ciphertext = [0u8; BLOCK_BYTES];
//! engine.process_block(&[0xff; BLOCK_BYTES], &mut ciphertext)?;
//! assert_eq!(ciphertext, [0x27, 0x8b, 0x27, 0xe4, 0x2e, 0x2f, 0x0d, 0x49]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod cipher;
mod engine;
mod params;

pub use engine::Rc2Engine;
pub use params::Params;
pub use tc_params::Rc2Params;

/// RC2 block length in bytes (64 bits).
pub const BLOCK_BYTES: usize = 8;
/// Maximum RC2 key length in bytes.
pub const MAX_KEY_BYTES: usize = 128;
/// Maximum RC2 effective key size in bits.
pub const MAX_EFFECTIVE_KEY_BITS: usize = 1024;
