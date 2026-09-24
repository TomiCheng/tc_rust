//! RC5 single-block ciphers with 32-bit and 64-bit words.
//!
//! Both engines accept a variable-length key and a public round count through
//! [`Params`] or a caller-supplied [`Rc5Params`] implementation.

#![no_std]

mod cipher;
mod params;
mod rc5_32_engine;
mod rc5_64_engine;

pub use params::{Params, Rc5Params};
pub use rc5_32_engine::Rc532Engine;
pub use rc5_64_engine::Rc564Engine;

/// Standard RC5 round count.
pub const DEFAULT_ROUNDS: usize = 12;
/// Maximum RC5 round count defined by RFC 2040.
pub const MAX_ROUNDS: usize = 255;
/// Maximum RC5 key length in bytes.
pub const MAX_KEY_BYTES: usize = 255;
/// RC5-32 block length in bytes.
pub const RC5_32_BLOCK_BYTES: usize = 8;
/// RC5-64 block length in bytes.
pub const RC5_64_BLOCK_BYTES: usize = 16;

/// RC5-32 display name.
pub const RC5_32_ALGO_NAME: &str = "RC5-32";
/// RC5-64 display name.
pub const RC5_64_ALGO_NAME: &str = "RC5-64";
