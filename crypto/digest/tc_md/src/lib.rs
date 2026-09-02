//! MD2, MD4, and MD5 digest implementations for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod md2;
mod md4;
mod md5;
mod md_buffer;

pub use md2::Md2Digest;
pub use md4::Md4Digest;
pub use md5::Md5Digest;
