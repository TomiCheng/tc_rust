//! RFC 5649 key wrapping with padding over a 128-bit block cipher.

#![no_std]

mod engine;

pub use engine::Rfc5649WrapEngine;

/// RFC 5649 key-wrap operation error.
pub type Rfc5649Error<E> = tc_cipher::KeyWrapError<E>;
/// RFC 5649 key-wrapper initialization error.
pub type Rfc5649InitError<E> = tc_cipher::KeyWrapInitError<E>;
