//! BLAKE2（BLAKE2b、BLAKE2s、BLAKE2xs）與沿用 BLAKE2s 壓縮函數的 BLAKE3，建在 `tc_digest` 的 trait 上。

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod blake2b;
mod blake2s;
mod blake2xs;
mod blake3;
mod blake3_portable;
#[cfg(feature = "blake3")]
mod blake3_upstream;

pub use blake2b::Blake2bDigest;
pub use blake2s::Blake2sDigest;
pub use blake2xs::Blake2xsDigest;
// `self::` 避開與 `blake3` crate 同名的歧義。
pub use self::blake3::Blake3Digest;
pub use blake3_portable::Blake3PortableDigest;
#[cfg(feature = "blake3")]
pub use blake3_upstream::Blake3UpstreamDigest;
