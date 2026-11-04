//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.

mod default_algo;
mod default_algo_builder;
mod error;
mod traits;

pub use default_algo_builder::DefaultAlgoBuilder;
pub use error::{AlgoError, ErrorKind};
pub use traits::{Algo, AlgoBuilder, Cipher, CipherDirection, DigestFactory, Mac, Params};
