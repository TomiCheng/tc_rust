//! SM3 digest implementation for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod md_buffer;
mod sm3;

pub use sm3::Sm3Digest;
