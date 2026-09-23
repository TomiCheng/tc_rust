#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod block_error;
mod cipher_direction;
mod init_error;
mod traits;
mod key;

pub use traits::{BlockCipher, BlockCipherInit, KeyParams};
pub use block_error::BlockError;
pub use cipher_direction::CipherDirection;
pub use init_error::InitError;
pub use key::*;
