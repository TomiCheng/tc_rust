//! Haraka digest implementations for the tc_rust workspace.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

mod haraka;

pub use haraka::{Haraka256Digest, Haraka512Digest, HarakaError};
