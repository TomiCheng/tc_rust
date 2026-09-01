//! DSTU 7564 digest implementation for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod dstu7564;
mod md_buffer;

pub use dstu7564::Dstu7564Digest;
