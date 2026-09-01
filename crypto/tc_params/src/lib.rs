//! Shared cryptographic parameter abstractions.

#![no_std]

mod key;
mod key_with_s_box;

pub use key::{KeyOwned, KeyParams, KeyRef};
pub use key_with_s_box::KeyWithSBoxParams;
