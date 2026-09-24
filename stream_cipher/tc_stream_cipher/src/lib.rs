//! Shared interfaces for stream ciphers.

#![no_std]

mod cipher_direction;
mod init_error;
mod params;
mod stream_error;
mod traits;

pub use cipher_direction::CipherDirection;
pub use init_error::InitError;
pub use params::{IvParams, KeyParams};
pub use stream_error::StreamError;
pub use traits::{StreamCipher, StreamCipherInit};
