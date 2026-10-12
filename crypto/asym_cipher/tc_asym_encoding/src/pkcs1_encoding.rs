//! PKCS#1 v1.5 encoding over an asymmetric block cipher, as Bouncy Castle's
//! `Pkcs1Encoding`: one encoding with its block inline, and one, with the
//! `alloc` feature, with its block on the heap.

mod encoder;
mod fixed;
#[cfg(feature = "alloc")]
mod heap;

pub use fixed::FixedPkcs1Encoding;
#[cfg(feature = "alloc")]
pub use heap::Pkcs1Encoding;
