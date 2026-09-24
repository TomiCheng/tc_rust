//! RC2 single-block cipher with an independently selectable effective key size.
//!
//! [`Params::new`] uses the full supplied key length; [`Params::with_effective_key_bits`]
//! selects a size explicitly. Parameters are validated by the engine.

#![no_std]

mod cipher;
mod engine;
mod params;

pub use engine::Rc2Engine;
pub use params::{Params, Rc2Params};

/// RC2 block length in bytes (64 bits).
pub const BLOCK_BYTES: usize = 8;
/// Maximum RC2 key length in bytes.
pub const MAX_KEY_BYTES: usize = 128;
/// Maximum RC2 effective key size in bits.
pub const MAX_EFFECTIVE_KEY_BITS: usize = 1024;

/// Algorithm display name.
pub const ALGO_NAME: &str = "RC2";
