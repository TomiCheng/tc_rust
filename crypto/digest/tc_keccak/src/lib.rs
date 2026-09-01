//! Keccak, SHA-3, SHAKE, cSHAKE, ParallelHash, and TupleHash for the tc_rust workspace.

#![no_std]

extern crate alloc;

pub mod cshake;
pub mod keccak;
pub mod parallelhash;
pub mod sha3;
pub mod shake;
pub mod tuplehash;
mod xof_utils;

pub use cshake::CShakeDigest;
pub use keccak::KeccakDigest;
pub use parallelhash::ParallelHash;
pub use sha3::Sha3Digest;
pub use shake::ShakeDigest;
pub use tuplehash::TupleHash;
