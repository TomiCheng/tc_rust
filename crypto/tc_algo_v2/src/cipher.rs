#![cfg_attr(feature = "aes", doc = include_str!("../docs/AeadCipher.md"))]

mod algo;
mod cipher_entry;
mod cipher_provider;
mod cipher_trait;
mod default_cipher_provider;
mod empty_cipher_provider;
#[cfg(feature = "aes")]
mod params;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub use cipher_entry::CipherEntry;
pub use cipher_provider::CipherProvider;
pub use cipher_trait::{Cipher, CipherDirection};
pub(crate) use empty_cipher_provider::EmptyCipherProvider;
#[cfg(feature = "aes")]
pub use tc_aead_cipher::AeadParamsOwned;
#[cfg(feature = "aes")]
pub use tc_block_modes::{IvParams, KeyWithIvOwned};
