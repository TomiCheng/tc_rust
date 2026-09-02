//! RFC 3211 key wrapping over a caller-selected block cipher.

#![no_std]

extern crate alloc;

mod engine;

pub use engine::Rfc3211WrapEngine;

/// RFC 3211 key-wrap operation error.
pub type Rfc3211Error<E> = tc_cipher::KeyWrapError<E>;
/// RFC 3211 key-wrapper initialization error.
pub type Rfc3211InitError<E> = tc_cipher::KeyWrapInitError<E>;
