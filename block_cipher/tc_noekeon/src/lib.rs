//! Noekeon single-block encryption in direct-key mode.
//!
//! [`NoekeonEngine`] accepts a 16-byte key and processes 16-byte blocks.
//! Constant time with respect to key and block contents: the implementation
//! uses bitwise operations and fixed rotations, without secret-dependent
//! branches or table lookups. Direction and buffer lengths are public.
//!
//! The stored working key is wiped on drop; caller buffers and every copy in
//! registers or on the stack are not. This crate requires no allocator and
//! provides no mode, padding or authentication.

#![no_std]

mod cipher;
mod engine;

pub use engine::NoekeonEngine;

/// Noekeon block length in bytes (128 bits).
pub const BLOCK_BYTES: usize = 16;
/// Noekeon key length in bytes (128 bits).
pub const KEY_BYTES: usize = 16;
/// Algorithm name written by the engine's display implementation.
pub const ALGO_NAME: &str = "Noekeon";
