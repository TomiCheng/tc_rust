//! Core cipher abstractions for the `tc_rust` workspace.
//!
//! Operational cipher and key-wrapping traits are kept separate from their
//! initialization traits. This lets initialized implementations use trait
//! objects while retaining strongly typed initialization parameters.

#![no_std]

mod aead_cipher;
mod block_cipher;
mod cipher_direction;
mod key_wrap;
mod stream_cipher;

pub use aead_cipher::{AeadCipher, AeadCipherInit};
pub use block_cipher::{BlockCipher, BlockCipherInit};
pub use cipher_direction::CipherDirection;
pub use key_wrap::{KeyWrap, KeyWrapInit, WrapDirection};
pub use stream_cipher::{StreamCipher, StreamCipherInit};
