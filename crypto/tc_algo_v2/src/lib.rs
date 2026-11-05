//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.

pub mod cipher;
mod default_algo;
mod default_algo_builder;
pub mod digest;
mod error;
mod generate;
mod mac;
mod params;
mod policy;
mod traits;

pub use default_algo_builder::DefaultAlgoBuilder;
pub use error::{AlgoError, ErrorKind};
pub use params::{DefaultParamsOwned, DefaultParamsRef};
pub use policy::ListPolicy;
pub use traits::{
    Algo, AlgoBuilder, EntryBase, KeyGenerator, KeyGeneratorEntry, KeyGeneratorProvider, KeyPair,
    KeyPairGenerator, KeyPairGeneratorEntry, KeyPairGeneratorProvider, Mac, MacEntry, MacProvider,
    Params, Policy,
};
