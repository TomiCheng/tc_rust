//! Shared cipher abstractions.

#![no_std]

mod block_cipher;
mod block_error;
mod cipher_direction;
mod init_error;

pub use block_cipher::{BlockCipher, BlockCipherInit};
pub use block_error::BlockError;
pub use cipher_direction::CipherDirection;
pub use init_error::InitError;
