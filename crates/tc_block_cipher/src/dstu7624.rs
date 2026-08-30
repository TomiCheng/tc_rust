//! DSTU 7624:2014 (Kalyna) block cipher.
//!
//! Both sizes are expressed as compile-time counts of 64-bit words, so each
//! engine and parameter value stores only the selected variant's material. A key
//! may be the same size as the block or twice its size, subject to the
//! standard's 512-bit maximum, which leaves exactly five valid combinations;
//! any other pairing simply has no implementation and so cannot be written.
//!
//! ```
//! use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
//! use tc_block_cipher::{Dstu7624Engine, Dstu7624Params};
//!
//! let key: [u8; 16] = core::array::from_fn(|index| index as u8);
//! let input: [u8; 16] = core::array::from_fn(|index| index as u8 + 0x10);
//! let params = Dstu7624Params::<2>::new(&key)?;
//! let mut cipher = Dstu7624Engine::<2, 2>::new();
//! cipher.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut output = [0u8; 16];
//! cipher.process_block(&input, &mut output)?;
//! assert_eq!(output, [
//!     0x81, 0xBF, 0x1C, 0x7D, 0x77, 0x9B, 0xAC, 0x20,
//!     0xE1, 0xC9, 0xEA, 0x39, 0xB4, 0xD2, 0xAD, 0x06,
//! ]);
//! # Ok::<(), tc_block_cipher::BlockCipherError>(())
//! ```

use crate::BlockCipherError;

mod cipher;
mod engine;
mod params;
mod tables;

pub use engine::Dstu7624Engine;
pub use params::Dstu7624Params;

/// Internal marker used to select an exact-size round-key table.
#[doc(hidden)]
pub struct Dstu7624Config<const BLOCK_WORDS: usize, const KEY_WORDS: usize>;

/// Exact round-key storage for one valid block/key word-count combination.
#[doc(hidden)]
pub trait ValidDstu7624Config<const BLOCK_WORDS: usize> {
    /// Rounds run by this combination, which the key width alone decides.
    const ROUNDS: usize;

    /// Concrete fixed-size round-key table, holding `ROUNDS + 1` round keys.
    type Schedule;

    /// Creates a zeroed schedule.
    fn new_schedule() -> Self::Schedule;

    /// Views the schedule as round keys.
    fn schedule(schedule: &Self::Schedule) -> &[[u64; BLOCK_WORDS]];

    /// Mutably views the schedule as round keys.
    fn schedule_mut(schedule: &mut Self::Schedule) -> &mut [[u64; BLOCK_WORDS]];
}

/// Supported DSTU 7624 block lengths in bits.
pub const DSTU7624_BLOCK_BITS: [usize; 3] = [128, 256, 512];
/// Supported DSTU 7624 key lengths in bytes.
pub const DSTU7624_KEY_BYTES: [usize; 3] = [16, 32, 64];
