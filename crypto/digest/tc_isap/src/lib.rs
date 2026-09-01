//! ISAP hash implementation for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod ascon_core;
mod isap;

pub use isap::IsapDigest;
