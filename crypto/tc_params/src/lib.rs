//! Shared object-safe cryptographic parameter traits, including
//! algorithm-specific initialization parameters and convenience types.

#![no_std]

mod key;
mod key_with_iv;
mod key_with_s_box;
mod key_with_tweak;
mod rc2;
mod rc5;

pub use key::{KeyOwned, KeyParams, KeyRef};
pub use key_with_iv::{KeyWithIvOwned, KeyWithIvParams, KeyWithIvRef};
pub use key_with_s_box::KeyWithSBoxParams;
pub use key_with_tweak::KeyWithTweakParams;
pub use rc2::Rc2Params;
pub use rc5::Rc5Params;
