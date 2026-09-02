//! SHA-1 and SHA-2 digest implementations for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod md_buffer;
mod sha1;
pub mod sha224;
pub mod sha256;
mod sha256_core;
pub mod sha384;
pub mod sha512;
mod sha512_core;
pub mod sha512t;

pub use sha1::Sha1Digest;
pub use sha224::Sha224Digest;
pub use sha256::Sha256Digest;
pub use sha384::Sha384Digest;
pub use sha512::Sha512Digest;
pub use sha512t::Sha512tDigest;
