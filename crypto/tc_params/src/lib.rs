//! Shared object-safe cryptographic parameter traits, including
//! algorithm-specific initialization parameters and convenience types.

#![no_std]

mod aead_block;
mod initial_aad;
mod iv;
mod key;
mod key_with_iv;
mod mac_size;
mod rc2;
mod rc5;
mod s_box;
mod tweak;

pub use aead_block::AeadBlockParams;
pub use initial_aad::InitialAadParams;
pub use iv::{IvParams, OptionalIvParams};
pub use key::{KeyOwned, KeyParams, KeyRef};
pub use key_with_iv::{KeyWithIvOwned, KeyWithIvRef};
pub use mac_size::MacSizeParams;
pub use rc2::Rc2Params;
pub use rc5::Rc5Params;
pub use s_box::SBoxParams;
pub use tweak::TweakParams;
