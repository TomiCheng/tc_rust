//! Message-digest adapters for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod null;
mod prehash;
mod shortened;

pub use null::NullDigest;
pub use prehash::{Prehash, PrehashError};
pub use shortened::ShortenedDigest;
