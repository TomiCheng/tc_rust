//! CAST5 (CAST-128) block cipher.
//!
//! CAST5 uses a 64-bit block and keys from 40 through 128 bits. Keys of at
//! most 80 bits use 12 rounds; longer keys use 16 rounds.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_block_cipher::{Cast5Engine, Cast5Params};
//!
//! let key = [
//!     0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
//!     0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A,
//! ];
//! let params = Cast5Params::new(&key)?;
//! let mut cipher = Cast5Engine::new();
//! cipher.init(true, &params)?;
//!
//! let mut output = [0u8; 8];
//! cipher.process_block(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF], &mut output)?;
//! assert_eq!(output, [0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2]);
//! # Ok::<(), tc_block_cipher::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod cipher;
mod engine;
mod params;
mod tables;

pub use engine::Cast5Engine;
pub use params::Cast5Params;

/// CAST5 block length in bytes (64 bits).
pub const CAST5_BLOCK_BYTES: usize = 8;
/// Minimum CAST5 key length in bytes (40 bits).
pub const CAST5_MIN_KEY_BYTES: usize = 5;
/// Maximum CAST5 key length in bytes (128 bits).
pub const CAST5_MAX_KEY_BYTES: usize = 16;
