//! RFC 3211 key wrapping over a caller-selected block cipher.

#![no_std]

extern crate alloc;

mod engine;
mod error;

pub use engine::Rfc3211WrapEngine;
pub use error::{Rfc3211Error, Rfc3211InitError};
