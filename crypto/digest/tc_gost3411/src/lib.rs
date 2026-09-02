//! GOST R 34.11-2012 digest implementations for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod gost3411_2012;

pub use gost3411_2012::{Gost3411_2012_256Digest, Gost3411_2012_512Digest};
