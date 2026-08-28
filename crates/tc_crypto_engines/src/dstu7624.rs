//! DSTU 7624:2014 (Kalyna) block cipher.
//!
//! The engine is configured for a 128-, 256-, or 512-bit block when created.
//! A key may be the same size as the block or twice its size, subject to the
//! standard's 512-bit maximum key size.
//!
//! ```
//! use tc_crypto_core::BlockCipher;
//! use tc_crypto_engines::{Dstu7624Engine, Dstu7624Params};
//!
//! let key: [u8; 16] = core::array::from_fn(|index| index as u8);
//! let input: [u8; 16] = core::array::from_fn(|index| index as u8 + 0x10);
//! let params = Dstu7624Params::new(&key)?;
//! let mut cipher = Dstu7624Engine::new(128)?;
//! cipher.init(true, &params)?;
//!
//! let mut output = [0u8; 16];
//! cipher.process_block(&input, &mut output)?;
//! assert_eq!(output, [
//!     0x81, 0xBF, 0x1C, 0x7D, 0x77, 0x9B, 0xAC, 0x20,
//!     0xE1, 0xC9, 0xEA, 0x39, 0xB4, 0xD2, 0xAD, 0x06,
//! ]);
//! # Ok::<(), tc_crypto_engines::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod cipher;
mod engine;
mod params;
mod tables;

pub use engine::Dstu7624Engine;
pub use params::Dstu7624Params;

/// Supported DSTU 7624 block lengths in bits.
pub const DSTU7624_BLOCK_BITS: [usize; 3] = [128, 256, 512];
/// Supported DSTU 7624 key lengths in bytes.
pub const DSTU7624_KEY_BYTES: [usize; 3] = [16, 32, 64];
