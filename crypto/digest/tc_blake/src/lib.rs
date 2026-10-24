//! BLAKE2（BLAKE2b、BLAKE2s、BLAKE2xs）與沿用 BLAKE2s 壓縮函數的 BLAKE3，建在 `tc_digest` 的 trait 上。

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod blake2b;
mod blake2s;
mod blake2xs;
mod blake3;

pub use blake2b::Blake2bDigest;
pub use blake2s::Blake2sDigest;
pub use blake2xs::Blake2xsDigest;
pub use blake3::Blake3Digest;
