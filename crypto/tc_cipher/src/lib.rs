//! Shared object-safe cipher contracts, operation directions, and processing
//! and initialization error types.

#![no_std]

mod aead_block_cipher;
mod aead_block_error;
mod aead_cipher;
mod aead_error;
mod block_cipher;
mod block_cipher_mode;
mod block_error;
mod block_mode_error;
mod block_mode_init_error;
mod cipher_direction;
mod init_error;
mod key_wrap;
mod key_wrap_error;
mod stream_cipher;
mod stream_error;

pub use aead_block_cipher::AeadBlockCipher;
pub use aead_block_error::{AeadBlockError, AeadBlockInitError};
pub use aead_cipher::{AeadCipher, AeadCipherInit};
pub use aead_error::AeadError;
pub use block_cipher::{BlockCipher, BlockCipherInit};
pub use block_cipher_mode::BlockCipherMode;
pub use block_error::BlockError;
pub use block_mode_error::BlockModeError;
pub use block_mode_init_error::BlockModeInitError;
pub use cipher_direction::CipherDirection;
pub use init_error::InitError;
pub use key_wrap::{KeyWrap, KeyWrapInit, WrapDirection};
pub use key_wrap_error::{KeyWrapError, KeyWrapInitError};
pub use stream_cipher::{StreamCipher, StreamCipherInit};
pub use stream_error::StreamError;
