//! GOST R 34.11-94 and GOST R 34.11-2012 digest implementations.

#![no_std]

extern crate alloc;

mod gost3411;
mod gost3411_2012;

pub use gost3411::Gost3411Digest;
pub use gost3411_2012::{Gost3411_2012_256Digest, Gost3411_2012_512Digest};
