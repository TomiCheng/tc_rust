//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.

pub mod cipher;
mod default_algo;
mod default_algo_builder;
mod default_algo_context;
pub mod digest;
mod error;
mod generate;
mod mac;
mod params;
mod policy;
mod traits;

pub use default_algo_builder::DefaultAlgoBuilder;
pub use default_algo_context::DefaultAlgoContext;
pub use error::{AlgoError, ErrorKind};
pub use generate::{
    KeyGenerator, KeyGeneratorEntry, KeyGeneratorProvider, KeyPair, KeyPairGenerator,
    KeyPairGeneratorEntry, KeyPairGeneratorProvider,
};
pub use mac::{Mac, MacEntry, MacProvider};
pub use policy::ListPolicy;
pub use traits::{Algo, AlgoBuilder, EntryBase, Params, Policy};
