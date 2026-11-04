//! Name- and OID-based factories for algorithms, after Bouncy Castle's `Org.BouncyCastle.Security`.

mod error;
mod traits;

pub use error::{AlgoError, ErrorKind};
pub use traits::{Algo, Cipher, CipherDirection, DigestFactory, Mac, Params};
