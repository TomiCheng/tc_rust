//! ISAAC stream cipher.

#![no_std]

mod engine;

pub use engine::IsaacEngine;

/// Maximum key length accepted by ISAAC, in bytes.
pub const MAX_KEY_BYTES: usize = 1024;
