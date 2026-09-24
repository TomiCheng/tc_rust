//! Generalized Rijndael single-block ciphers.
//!
//! Unlike AES, Rijndael supports 128-, 160-, 192-, 224- and 256-bit blocks
//! and keys in any combination. The engine type fixes the block size.
//! Import `tc_block_cipher::{BlockCipher, BlockCipherInit}` to use an engine.

#![no_std]

mod engine;
mod tables;

pub use engine::{
    Rijndael128Engine, Rijndael160Engine, Rijndael192Engine, Rijndael224Engine, Rijndael256Engine,
    RijndaelEngine,
};

/// Supported block lengths in bits.
pub const BLOCK_BITS: [usize; 5] = [128, 160, 192, 224, 256];
/// Supported key lengths in bytes.
pub const KEY_BYTES: [usize; 5] = [16, 20, 24, 28, 32];
/// Algorithm display name.
pub const ALGO_NAME: &str = "Rijndael";
