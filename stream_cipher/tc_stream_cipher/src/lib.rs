//! Shared interfaces for stream ciphers.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod cipher_direction;
mod init_error;
mod params;
mod stream_error;
mod traits;

pub use cipher_direction::CipherDirection;
pub use init_error::InitError;
pub use params::{KeyFixed, KeyRef, KeyWithIvFixed, KeyWithIvRef};
#[cfg(feature = "alloc")]
pub use params::{KeyOwned, KeyWithIvOwned};
pub use stream_error::StreamError;
pub use traits::{IvParams, KeyParams, StreamCipher, StreamCipherInit};
