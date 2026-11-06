//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.

pub mod cipher;
mod default_algo;
mod default_algo_builder;
mod default_algo_context;
mod default_provider;
pub mod digest;
mod error;
mod generate;
mod mac;
#[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
mod params;
mod policy;
mod traits;
mod wrap;
mod xof;

pub use default_algo_builder::DefaultAlgoBuilder;
pub use default_algo_context::DefaultAlgoContext;
pub use error::{AlgoError, ErrorKind};
pub use generate::{
    KeyGenerator, KeyGeneratorEntry, KeyGeneratorProvider, KeyLength, KeyPair, KeyPairGenerator,
    KeyPairGeneratorEntry, KeyPairGeneratorProvider,
};
#[cfg(feature = "rsa")]
pub use generate::{RsaKey, RsaKeyGenerationParamsOwned};
pub use mac::{Mac, MacEntry, MacProvider};
pub use policy::ListPolicy;
#[cfg(any(feature = "aes", feature = "chacha", feature = "hmac-sha256"))]
pub use tc_block_cipher::{KeyOwned, KeyParams};
pub use traits::{Algo, AlgoBuilder, EntryBase, Params, Policy};
pub use wrap::{WrapDirection, Wrapper, WrapperEntry, WrapperProvider};
pub use xof::{Xof, XofEntry, XofProvider};
