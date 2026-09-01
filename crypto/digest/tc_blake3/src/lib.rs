//! BLAKE3 digest and extendable-output function for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod blake3;

pub use blake3::Blake3Digest;
