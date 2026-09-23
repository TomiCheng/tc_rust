#![no_std]

mod common;
mod light_engine;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod table_engine;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_engine;

pub use light_engine::AesLightEngine;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::AesRustCryptoEngine;
pub use table_engine::AesTableEngine;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86_engine::AesX86Engine;

/// AES block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// Accepted key lengths in bytes (128, 192, and 256 bits).
pub const KEY_BYTES: [usize; 3] = [16, 24, 32];
