//! CAST5 (CAST-128) and CAST6 (CAST-256) block ciphers.

#![no_std]

pub mod cast5;
pub mod cast6;
mod common;

pub use cast5::Cast5Engine;
pub use cast6::Cast6Engine;
