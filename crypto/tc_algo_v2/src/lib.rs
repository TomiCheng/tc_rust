//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.

mod agreement;
pub mod cipher;
mod default_algo;
mod default_algo_builder;
mod default_algo_context;
mod default_provider;
pub mod digest;
mod error;
mod generate;
mod mac;
pub mod params;
mod policy;
mod traits;
mod wrap;
mod xof;

pub use agreement::{Agreement, AgreementEntry, AgreementProvider, SharedSecret};
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
pub use wrap::{WrapDirection, Wrapper, WrapperEntry, WrapperProvider};
pub use xof::{Xof, XofEntry, XofProvider};
