//! Shared cipher abstractions.

#![no_std]

mod block_cipher;
mod cipher_direction;

pub use block_cipher::{BlockCipher, BlockCipherInit};
pub use cipher_direction::CipherDirection;
