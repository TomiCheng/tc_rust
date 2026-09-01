//! Shared object-safe cipher contracts, operation directions, and processing
//! and initialization error types.

#![no_std]

mod block_cipher;
mod block_error;
mod cipher_direction;
mod init_error;
mod stream_cipher;
mod stream_error;

pub use block_cipher::{BlockCipher, BlockCipherInit};
pub use block_error::BlockError;
pub use cipher_direction::CipherDirection;
pub use init_error::InitError;
pub use stream_cipher::{StreamCipher, StreamCipherInit};
pub use stream_error::StreamError;
