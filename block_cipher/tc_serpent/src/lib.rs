//! Serpent and Tnepres single-block encryption.
//!
//! Constant time with respect to key and block contents: both engines use
//! bitsliced S-boxes and fixed rotations. Tnepres uses a different byte
//! representation, not an alias for Serpent. Key lengths are public.
//! Stored schedules are wiped on drop, but caller buffers and every register
//! or stack copy are not. No mode, padding or authentication is provided.

#![no_std]

mod cipher;
mod serpent_engine;
mod tnepres_engine;

pub use serpent_engine::SerpentEngine;
pub use tnepres_engine::TnepresEngine;

/// Block length in bytes.
pub const BLOCK_BYTES: usize = 16;
/// Minimum key length in bytes.
pub const MIN_KEY_BYTES: usize = 4;
/// Maximum key length in bytes.
pub const MAX_KEY_BYTES: usize = 32;
/// Accepted key lengths advance by this many bytes.
pub const KEY_STEP_BYTES: usize = 4;
/// Algorithm name of the conventional representation.
pub const SERPENT_ALGO_NAME: &str = "Serpent";
/// Algorithm name of the reversed representation.
pub const TNEPRES_ALGO_NAME: &str = "Tnepres";
