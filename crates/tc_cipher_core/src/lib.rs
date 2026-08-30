//! Core cipher abstractions for the `tc_rust` workspace.
//!
//! The operational cipher and key-wrapping traits are kept separate from their
//! initialization traits. This lets initialized implementations be used through
//! trait objects while retaining strongly typed initialization parameters.

#![no_std]

mod block_cipher;
mod key_wrap;
mod stream_cipher;

pub use block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
pub use key_wrap::{KeyWrap, KeyWrapInit, WrapDirection};
pub use stream_cipher::{StreamCipher, StreamCipherInit};
