//! RIPEMD digest implementations for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod md_buffer;
pub mod ripemd128;
pub mod ripemd160;
pub mod ripemd256;
pub mod ripemd320;
mod ripemd_common;

pub use ripemd128::RipeMD128Digest;
pub use ripemd160::RipeMD160Digest;
pub use ripemd256::RipeMD256Digest;
pub use ripemd320::RipeMD320Digest;
