//! Generalised Rijndael block cipher, ported from Bouncy Castle's
//! `RijndaelEngine` (the pre-NIST reference form).
//!
//! Unlike the AES engine, this supports the full Rijndael parameter space: block
//! and key sizes of 128, 160, 192, 224, or 256 bits in any combination. Both
//! sizes are expressed as compile-time counts of 32-bit columns, so each engine
//! and parameter value stores only the selected variant's material.
//!
//! The state is held as four 64-bit "rows" of `block_bits / 4` bits each, exactly
//! as the reference implementation packs it.
//!
//! ```
//! use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_block_cipher::{RijndaelEngine, RijndaelParams};
//!
//! // 128-bit block, 128-bit key.
//! let key = [
//!     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//! let params = RijndaelParams::<4>::new(&key)?;
//! let mut cipher = RijndaelEngine::<4, 4>::new();
//! cipher.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut ciphertext = [0u8; 16];
//! cipher.process_block(&[0u8; 16], &mut ciphertext)?;
//! assert_eq!(ciphertext, [
//!     0x0E, 0xDD, 0x33, 0xD3, 0xC6, 0x21, 0xE5, 0x46,
//!     0x45, 0x5B, 0xD8, 0xBA, 0x14, 0x18, 0xBE, 0xC8,
//! ]);
//! # Ok::<(), tc_block_cipher::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod engine;
mod params;
mod tables;

pub use engine::RijndaelEngine;
pub use params::RijndaelParams;

/// Internal marker used to select an exact-size round-key table.
#[doc(hidden)]
pub struct RijndaelConfig<const BLOCK_COLUMNS: usize, const KEY_COLUMNS: usize>;

/// Exact round-key storage for one valid block/key column combination.
#[doc(hidden)]
pub trait ValidRijndaelConfig<const BLOCK_COLUMNS: usize> {
    /// Concrete fixed-size round-key table.
    type Schedule;

    /// Creates a zeroed schedule.
    fn new_schedule() -> Self::Schedule;

    /// Views the schedule as round keys.
    fn schedule(schedule: &Self::Schedule) -> &[[u32; BLOCK_COLUMNS]];

    /// Mutably views the schedule as round keys.
    fn schedule_mut(schedule: &mut Self::Schedule) -> &mut [[u32; BLOCK_COLUMNS]];
}

/// Supported Rijndael block lengths in bits.
pub const RIJNDAEL_BLOCK_BITS: [usize; 5] = [128, 160, 192, 224, 256];
/// Supported Rijndael key lengths in bytes.
pub const RIJNDAEL_KEY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];
