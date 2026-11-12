#![cfg_attr(feature = "aes", doc = include_str!("../docs/AeadCipher.md"))]
#![cfg_attr(feature = "chacha", doc = include_str!("../docs/StreamCipher.md"))]
#![cfg_attr(feature = "ies", doc = include_str!("../docs/IES.md"))]

mod algo;
mod cipher_entry;
mod cipher_provider;
mod cipher_trait;
mod default_cipher_provider;
mod empty_cipher_provider;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub use cipher_entry::CipherEntry;
pub use cipher_provider::CipherProvider;
pub use cipher_trait::{Cipher, CipherDirection};
pub(crate) use empty_cipher_provider::EmptyCipherProvider;
