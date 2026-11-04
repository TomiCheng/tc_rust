//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.

mod default_algo;
mod default_algo_builder;
mod digest;
mod error;
mod generate;
mod mac;
mod traits;

pub use default_algo_builder::DefaultAlgoBuilder;
pub use error::{AlgoError, ErrorKind};
pub use traits::{
    Algo, AlgoBuilder, Cipher, CipherDirection, Digest, DigestEntry, DigestProvider, KeyGenerator,
    KeyGeneratorEntry, KeyGeneratorProvider, KeyPair, KeyPairGenerator, KeyPairGeneratorEntry,
    KeyPairGeneratorProvider, Mac, MacEntry, MacProvider, Params,
};
