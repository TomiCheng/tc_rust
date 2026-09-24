//! RC6-32/20 single-block encryption with 1- to 255-byte keys.
//!
//! Constant time under the hardware requirements documented on [`Rc6Engine`].
//! Stored subkeys are wiped on drop, but caller buffers and every register or
//! stack copy are not. No mode, padding or authentication is provided.

#![no_std]

mod cipher;
mod engine;

pub use engine::Rc6Engine;

/// RC6 block length in bytes.
pub const BLOCK_BYTES: usize = 16;
/// RC6 round count.
pub const ROUNDS: usize = 20;
/// Maximum accepted RC6 key length in bytes.
pub const MAX_KEY_BYTES: usize = 255;
/// Algorithm name written by the engine.
pub const ALGO_NAME: &str = "RC6";
