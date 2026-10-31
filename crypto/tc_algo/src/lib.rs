//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.

pub mod agreement;
pub mod cipher;
pub mod codec;
pub mod digest;
mod error;
pub mod generate;
pub mod kem;
pub mod key;
pub mod mac;
pub mod pbe;
pub mod signer;
pub mod wrap;
pub mod xof;

pub use error::{AlgoError, ErrorKind};
