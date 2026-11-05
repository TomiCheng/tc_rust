//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.

mod cipher;
mod default_algo;
mod default_algo_builder;
mod digest;
mod error;
mod generate;
mod mac;
mod policy;
mod traits;

pub use default_algo_builder::DefaultAlgoBuilder;
pub use error::{AlgoError, ErrorKind};
pub use policy::ListPolicy;
pub use traits::{
    Algo, AlgoBuilder, Cipher, CipherDirection, CipherEntry, CipherProvider, Digest, DigestEntry,
    DigestProvider, EntryBase, KeyGenerator, KeyGeneratorEntry, KeyGeneratorProvider, KeyPair,
    KeyPairGenerator, KeyPairGeneratorEntry, KeyPairGeneratorProvider, Mac, MacEntry, MacProvider,
    Params, Policy,
};
