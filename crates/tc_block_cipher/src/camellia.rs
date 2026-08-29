//! Camellia-128, Camellia-192, and Camellia-256 block cipher.
//!
//! [`CamelliaEngine`] is the four-T-table implementation corresponding to
//! Bouncy Castle's `CamelliaEngine`. [`CamelliaLightEngine`] uses a single
//! 256-byte S-box and computes the remaining transforms at runtime.
//!
//! ```
//! use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_block_cipher::{CamelliaEngine, CamelliaParams};
//!
//! let key = [
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
//!     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
//! ];
//! let params = CamelliaParams::new(&key)?;
//! let mut cipher = CamelliaEngine::new();
//! cipher.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut output = [0u8; 16];
//! cipher.process_block(&key, &mut output)?;
//! assert_eq!(output, [
//!     0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
//!     0x08, 0x57, 0x06, 0x56, 0x48, 0xEA, 0xBE, 0x43,
//! ]);
//! # Ok::<(), tc_block_cipher::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod cipher;
mod engine;
mod light_engine;
mod params;

pub use engine::CamelliaEngine;
pub use light_engine::CamelliaLightEngine;
pub use params::CamelliaParams;

/// Camellia block length in bytes (128 bits).
pub const CAMELLIA_BLOCK_BYTES: usize = 16;
