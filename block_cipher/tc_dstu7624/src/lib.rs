//! DSTU 7624:2014 (Kalyna) block cipher.

#![no_std]

mod cipher;
mod engine;
mod tables;

pub use engine::{Dstu7624Engine, Dstu7624Engine128, Dstu7624Engine256, Dstu7624Engine512};

/// Supported DSTU 7624 block lengths in bits.
pub const BLOCK_BITS: [usize; 3] = [128, 256, 512];
/// Supported DSTU 7624 key lengths in bytes.
pub const KEY_BYTES: [usize; 3] = [16, 32, 64];

/// Algorithm display name.
pub const ALGO_NAME: &str = "DSTU7624";
