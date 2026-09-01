//! BLAKE2 digest and extendable-output functions for the tc_rust workspace.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

pub mod blake2b;
pub mod blake2s;
pub mod blake2xs;

pub use blake2b::Blake2bDigest;
pub use blake2s::Blake2sDigest;
pub use blake2xs::Blake2xsDigest;
