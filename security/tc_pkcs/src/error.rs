use core::error::Error;
use core::fmt;

use tc_algo::AlgoError;
use tc_asn1::Asn1Error;
use tc_x509::X509Error;

// The error of this crate, wrapping those of the crates underneath
#[derive(Debug)]
#[non_exhaustive]
pub enum PkcsError {
    Algo(AlgoError),
    Asn1(Asn1Error),
    X509(X509Error),
    // No row knows the key
    UnknownPrivateKey,
    // A public key was given where a private one is needed
    NotPrivateKey,
    // The encoding of a private key is not what its algorithm requires
    InvalidPrivateKey,
    // No row knows the encryption scheme
    UnknownEncryption,
    // The params of an encryption scheme are not of its type, or not what it requires
    InvalidEncryptionParams,
}

impl fmt::Display for PkcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Algo(error) => write!(f, "{error}"),
            Self::Asn1(error) => write!(f, "{error}"),
            Self::X509(error) => write!(f, "{error}"),
            Self::UnknownPrivateKey => f.write_str("no row knows the private key"),
            Self::NotPrivateKey => f.write_str("a private key is needed"),
            Self::InvalidPrivateKey => f.write_str("invalid private key encoding"),
            Self::UnknownEncryption => f.write_str("no row knows the encryption scheme"),
            Self::InvalidEncryptionParams => f.write_str("invalid encryption scheme parameters"),
        }
    }
}

impl Error for PkcsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Algo(error) => Some(error),
            Self::Asn1(error) => Some(error),
            Self::X509(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AlgoError> for PkcsError {
    fn from(error: AlgoError) -> Self {
        Self::Algo(error)
    }
}

impl From<Asn1Error> for PkcsError {
    fn from(error: Asn1Error) -> Self {
        Self::Asn1(error)
    }
}

impl From<X509Error> for PkcsError {
    fn from(error: X509Error) -> Self {
        Self::X509(error)
    }
}
