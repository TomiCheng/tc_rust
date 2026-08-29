//! Core cipher abstractions for the `tc_rust` workspace.
//!
//! The operational cipher traits are kept separate from their initialization
//! traits. This lets initialized ciphers be used through trait objects while
//! implementations retain strongly typed initialization parameters.

#![no_std]

mod block_cipher;
mod stream_cipher;

pub use block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
pub use stream_cipher::{StreamCipher, StreamCipherInit};
