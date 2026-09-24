//! CAST5 and CAST6 single-block ciphers.
//!
//! CAST5 accepts 5- to 16-byte keys and has an 8-byte block. CAST6 accepts
//! 16-, 20-, 24-, 28- and 32-byte keys and has a 16-byte block.
//! Import `tc_block_cipher::{BlockCipher, BlockCipherInit}` to use the engines.

#![no_std]

pub mod cast5;
pub mod cast6;
mod common;

pub use cast5::Cast5Engine;
pub use cast6::Cast6Engine;
