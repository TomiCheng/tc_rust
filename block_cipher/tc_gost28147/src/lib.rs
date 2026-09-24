//! GOST 28147-89 single-block cipher with caller-selected S-boxes.
//!
//! Keys are 32 bytes and blocks are 8 bytes. The S-box is a parameter;
//! choosing a different table changes the cipher. Standard tables live in [`s_box`].
//! [`KeyWithSBox`] defaults to [`s_box::DEFAULT`]; custom parameter types
//! implement `tc_block_cipher::KeyParams` and [`SBoxParams`].

#![no_std]

mod cipher;
mod engine;
mod params;
pub mod s_box;

pub use engine::Gost28147Engine;
pub use params::{KeyWithSBox, SBoxParams};

/// Block length in bytes.
pub const BLOCK_BYTES: usize = 8;
/// Required key length in bytes.
pub const KEY_BYTES: usize = 32;
/// Algorithm display name.
pub const ALGO_NAME: &str = "Gost28147";
