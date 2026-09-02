//! Whirlpool digest implementation for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod md_buffer;
mod whirlpool;

pub use whirlpool::WhirlpoolDigest;
