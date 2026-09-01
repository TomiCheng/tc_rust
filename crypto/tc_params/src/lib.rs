//! Shared cryptographic parameter traits and convenience types.

#![no_std]

mod key;
mod key_with_s_box;
mod rc2;

pub use key::{KeyOwned, KeyParams, KeyRef};
pub use key_with_s_box::KeyWithSBoxParams;
pub use rc2::Rc2Params;
