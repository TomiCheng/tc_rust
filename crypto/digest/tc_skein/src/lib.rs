//! Skein 1.3 message digest.

#![no_std]

extern crate alloc;

mod engine;
mod skein;

pub use engine::SkeinEngine;
pub use skein::SkeinDigest;

/// Skein-256 internal state size in bits.
pub const SKEIN_256: usize = 256;
/// Skein-512 internal state size in bits.
pub const SKEIN_512: usize = 512;
/// Skein-1024 internal state size in bits.
pub const SKEIN_1024: usize = 1024;
