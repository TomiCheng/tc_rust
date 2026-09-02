//! Camellia-128, Camellia-192, and Camellia-256 block cipher.

#![no_std]

mod cipher;
mod engine;
mod light_engine;

pub use engine::CamelliaEngine;
pub use light_engine::CamelliaLightEngine;

/// Camellia block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
