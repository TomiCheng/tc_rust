mod algo;
mod default_key_generator_provider;
mod empty_key_generator_provider;
mod empty_key_pair_generator_provider;
mod key_generator;
mod key_generator_entry;
mod key_generator_provider;
mod key_length;
mod key_pair_generator;
mod key_pair_generator_entry;
mod key_pair_generator_provider;

pub(crate) use algo::BUILT_IN_KEY_GENERATORS;
pub(crate) use default_key_generator_provider::DefaultKeyGeneratorProvider;
pub(crate) use empty_key_generator_provider::EmptyKeyGeneratorProvider;
pub(crate) use empty_key_pair_generator_provider::EmptyKeyPairGeneratorProvider;
pub use key_generator::KeyGenerator;
pub use key_generator_entry::KeyGeneratorEntry;
pub use key_generator_provider::KeyGeneratorProvider;
pub use key_length::KeyLength;
pub use key_pair_generator::{KeyPair, KeyPairGenerator};
pub use key_pair_generator_entry::KeyPairGeneratorEntry;
pub use key_pair_generator_provider::KeyPairGeneratorProvider;

pub(crate) type CreateKeyGeneratorRows =
    fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>>;
