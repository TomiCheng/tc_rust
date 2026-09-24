//! Threefish tweakable single-block ciphers.
//!
//! The 256-, 512- and 1024-bit variants require a block-sized key and an
//! optional 16-byte tweak. An absent tweak is equivalent to sixteen zero bytes.

#![no_std]

mod cipher;
mod engine;
mod params;

pub use engine::{Threefish256Engine, Threefish512Engine, Threefish1024Engine, ThreefishEngine};
pub use params::{Params, TweakParams};

/// Fixed tweak length in bytes.
pub const TWEAK_BYTES: usize = 16;
/// Threefish-256 display name.
pub const THREEFISH_256_ALGO_NAME: &str = "Threefish-256";
/// Threefish-512 display name.
pub const THREEFISH_512_ALGO_NAME: &str = "Threefish-512";
/// Threefish-1024 display name.
pub const THREEFISH_1024_ALGO_NAME: &str = "Threefish-1024";
