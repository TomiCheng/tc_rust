//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.

pub mod agreement;
pub mod cipher;
mod default_algo;
mod default_algo_builder;
mod default_algo_context;
mod default_provider;
pub mod digest;
pub mod drbg;
mod error;
pub mod generate;
pub mod kdf;
pub mod kem;
pub mod mac;
pub mod params;
pub mod pbe;
mod policy;
pub mod signer;
mod traits;
pub mod wrap;
pub mod xof;

pub use default_algo_builder::DefaultAlgoBuilder;
pub use default_algo_context::DefaultAlgoContext;
pub use error::{AlgoError, ErrorKind};
pub use policy::ListPolicy;
pub use traits::{Algo, AlgoBuilder, EntryBase, Params, Policy};
