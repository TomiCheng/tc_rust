//! Core cipher abstractions for the `tc_rust` workspace.
//!
//! The operational cipher traits are kept separate from their initialization
//! traits. This lets initialized ciphers be used through trait objects while
//! implementations retain strongly typed initialization parameters.

#![no_std]

mod stream_cipher;

pub use stream_cipher::{StreamCipher, StreamCipherInit};
