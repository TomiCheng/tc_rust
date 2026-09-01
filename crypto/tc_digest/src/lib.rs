//! Shared message-digest contracts.

#![no_std]

mod digest;
mod xof;

pub use digest::{Digest, TryDigest};
pub use xof::{TryXof, Xof};
