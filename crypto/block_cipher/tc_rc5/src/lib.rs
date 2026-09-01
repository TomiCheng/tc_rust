//! RC5 block ciphers with 32-bit and 64-bit words.
//!
//! RC5 uses a variable-length key and caller-selected round count. Both engines
//! accept [`Rc5Params`], so callers may use [`Params`] or provide their own
//! parameter type.
//!
//! ```
//! use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_rc5::{Params, Rc532Engine};
//!
//! let params = Params::new(&[0x00], 2);
//! let mut engine = Rc532Engine::new();
//! engine.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut ciphertext = [0u8; 8];
//! engine.process_block(&[0u8; 8], &mut ciphertext)?;
//! assert_eq!(ciphertext, [0xdc, 0xa2, 0x69, 0x4b, 0xf4, 0x0e, 0x07, 0x88]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

mod cipher;
mod engine;
mod params;

pub use engine::{Rc532Engine, Rc564Engine};
pub use params::Params;
pub use tc_params::Rc5Params;

/// Standard RC5 round count.
pub const DEFAULT_ROUNDS: usize = 12;
/// Maximum RC5 round count defined by RFC 2040.
pub const MAX_ROUNDS: usize = 255;
/// Maximum RC5 key length in bytes.
pub const MAX_KEY_BYTES: usize = 255;
/// RC5-32 block length in bytes.
pub const RC5_32_BLOCK_BYTES: usize = 8;
/// RC5-64 block length in bytes.
pub const RC5_64_BLOCK_BYTES: usize = 16;
