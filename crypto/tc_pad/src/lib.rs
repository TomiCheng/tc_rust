//! Shared block-cipher padding contracts and the common padding error type.

#![no_std]

mod padding;
mod padding_error;

pub use padding::{BlockCipherPadding, BlockCipherPaddingInit};
pub use padding_error::PaddingError;
