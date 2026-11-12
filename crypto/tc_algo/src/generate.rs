#![cfg_attr(feature = "rsa", doc = include_str!("../docs/Rsa.md"))]

mod algo;
mod default_key_generator_provider;
mod default_key_pair_generator_provider;
mod empty_key_generator_provider;
mod empty_key_pair_generator_provider;
mod key_generator;
mod key_generator_entry;
mod key_generator_provider;
mod key_pair_generator;
mod key_pair_generator_entry;
mod key_pair_generator_provider;

pub(crate) use algo::{BUILT_IN_KEY_GENERATORS, BUILT_IN_KEY_PAIR_GENERATORS};
pub(crate) use empty_key_generator_provider::EmptyKeyGeneratorProvider;
pub(crate) use empty_key_pair_generator_provider::EmptyKeyPairGeneratorProvider;
pub use key_generator::KeyGenerator;
pub use key_generator_entry::KeyGeneratorEntry;
pub use key_generator_provider::KeyGeneratorProvider;
pub use key_pair_generator::{KeyPair, KeyPairGenerator};
pub use key_pair_generator_entry::KeyPairGeneratorEntry;
pub use key_pair_generator_provider::KeyPairGeneratorProvider;

pub(crate) type CreateKeyGeneratorRows =
    fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>>;
pub(crate) type CreateKeyPairGeneratorRows =
    fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>>;
