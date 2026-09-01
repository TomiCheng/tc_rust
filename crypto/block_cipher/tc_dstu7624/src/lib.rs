//! DSTU 7624:2014 (Kalyna) block cipher.

#![no_std]

mod cipher;
mod engine;
mod tables;

pub use engine::{Engine, Engine128, Engine256, Engine512};

/// Supported DSTU 7624 block lengths in bits.
pub const BLOCK_BITS: [usize; 3] = [128, 256, 512];
/// Supported DSTU 7624 key lengths in bytes.
pub const KEY_BYTES: [usize; 3] = [16, 32, 64];
