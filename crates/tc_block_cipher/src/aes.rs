//! AES-128, AES-192, and AES-256 block cipher.
//!
//! The portable T-table implementation is always available. With the default
//! `std` feature on x86/x86_64, [`AesEngine`] detects AES-NI at runtime and uses
//! it when available. Builds without default features always use the portable
//! T-table backend. Construct [`AesLightEngine`] when the caller explicitly
//! wants the small-footprint implementation even when AES-NI is available.
//!
//! ```
//! use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_block_cipher::{AesEngine, AesParams};
//!
//! let params = AesParams::new(&[0u8; 16])?;
//! let mut cipher = AesEngine::new();
//! cipher.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut output = [0u8; 16];
//! cipher.process_block(&[0u8; 16], &mut output)?;
//! # Ok::<(), tc_block_cipher::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod engine;
mod light_engine;
mod params;
mod portable;

#[cfg(all(
    not(feature = "force-portable-aes"),
    any(target_arch = "x86", target_arch = "x86_64")
))]
mod x86;

pub use engine::AesEngine;
pub use light_engine::AesLightEngine;
pub use params::AesParams;

/// AES block length in bytes (128 bits).
pub const AES_BLOCK_BYTES: usize = 16;

pub(crate) const MAX_ROUND_KEYS: usize = 15;
pub(crate) type RoundKeys = [[u8; AES_BLOCK_BYTES]; MAX_ROUND_KEYS];
