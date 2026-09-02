//! Shared object-safe cryptographic parameter traits, including
//! algorithm-specific initialization parameters and convenience types.

#![no_std]

mod aad_length;
mod initial_aad;
mod iv;
mod key;
mod key_with_iv;
mod rc2;
mod rc5;
mod s_box;
mod tweak;

pub use aad_length::AadLengthParams;
pub use initial_aad::InitialAadParams;
pub use iv::{IvParams, OptionalIvParams};
pub use key::{KeyOwned, KeyParams, KeyRef};
pub use key_with_iv::{KeyWithIvOwned, KeyWithIvRef};
pub use rc2::Rc2Params;
pub use rc5::Rc5Params;
pub use s_box::SBoxParams;
pub use tweak::TweakParams;
