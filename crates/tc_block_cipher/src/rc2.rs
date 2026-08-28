//! RC2 64-bit block cipher (RFC 2268), ported from Bouncy Castle's `RC2Engine`.
//!
//! RC2 has a variable-length key whose *effective* strength can be capped
//! independently of the supplied key bytes. [`Rc2Params::new`] takes the
//! effective size to be the full key length; [`Rc2Params::with_effective_key_bits`]
//! sets it explicitly (RFC 2268's "effective key bits").
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_block_cipher::{Rc2Engine, Rc2Params};
//!
//! // RFC 2268 vector: 8-byte key, 64 effective bits.
//! let key = [0xFFu8; 8];
//! let params = Rc2Params::new(&key)?;
//! let mut cipher = Rc2Engine::new();
//! cipher.init(true, &params)?;
//!
//! let mut ciphertext = [0u8; 8];
//! cipher.process_block(&[0xFFu8; 8], &mut ciphertext)?;
//! assert_eq!(ciphertext, [0x27, 0x8b, 0x27, 0xe4, 0x2e, 0x2f, 0x0d, 0x49]);
//! # Ok::<(), tc_block_cipher::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod engine;
mod params;

pub use engine::Rc2Engine;
pub use params::Rc2Params;

/// RC2 block length in bytes (64 bits).
pub const RC2_BLOCK_BYTES: usize = 8;
/// Maximum RC2 key length in bytes.
pub const RC2_MAX_KEY_BYTES: usize = 128;
/// Maximum RC2 effective key size in bits.
pub const RC2_MAX_EFFECTIVE_KEY_BITS: usize = 1024;
