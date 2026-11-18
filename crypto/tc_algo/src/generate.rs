#![cfg_attr(feature = "aes", doc = include_str!("../docs/KeyGeneration.md"))]
#![cfg_attr(feature = "rsa", doc = include_str!("../docs/KeyPairGeneration.md"))]
#![cfg_attr(all(feature = "rsa", feature = "sha"), doc = include_str!("../docs/Rsa.md"))]
#![cfg_attr(feature = "elgamal", doc = include_str!("../docs/ElGamal.md"))]
#![cfg_attr(feature = "naccache-stern", doc = include_str!("../docs/NaccacheStern.md"))]
#![cfg_attr(feature = "sm2", doc = include_str!("../docs/Sm2.md"))]
#![cfg_attr(all(feature = "dsa", feature = "sha"), doc = include_str!("../docs/Dsa.md"))]
#![cfg_attr(feature = "gost3410", doc = include_str!("../docs/Gost3410.md"))]
#![cfg_attr(feature = "cfrg-curves", doc = include_str!("../docs/EdDSA.md"))]
#![cfg_attr(feature = "ml-dsa", doc = include_str!("../docs/MlDsa.md"))]
#![cfg_attr(feature = "slh-dsa", doc = include_str!("../docs/SlhDsa.md"))]
#![cfg_attr(all(feature = "ecdsa", feature = "fp-custom", feature = "sha"), doc = include_str!("../docs/Ec.md"))]

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
pub use tc_asym_cipher::KeyPairGeneratorInit;

pub(crate) type CreateKeyGeneratorRows =
    fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn KeyGeneratorEntry>>;
pub(crate) type CreateKeyPairGeneratorRows =
    fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn KeyPairGeneratorEntry>>;
