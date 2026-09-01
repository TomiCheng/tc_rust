//! Tiger digest implementation for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod md_buffer;
mod tiger;

pub use tiger::TigerDigest;
