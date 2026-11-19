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
    // A field that generating needs was not set
    MissingField(&'static str),
    // A certification request whose extensionRequest is not a single Extensions
    InvalidRequest,
    // A signature that does not verify
    InvalidSignature,
    // A PKCS#12 file with a MAC or encrypted contents was loaded without a password
    MissingPassword,
    // The MAC of a PKCS#12 file does not verify: a wrong password or a changed file
    InvalidMac,
    // A PKCS#12 file whose structure is not what Bouncy Castle reads
    InvalidStore,
    // A key entry was set without a certificate chain
    NoCertificateChain,
    // A certificate entry was set under the alias of a key
    AliasInUse,
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
            Self::MissingField(field) => write!(f, "missing field: {field}"),
            Self::InvalidRequest => f.write_str("invalid certification request"),
            Self::InvalidSignature => f.write_str("the signature does not verify"),
            Self::MissingPassword => f.write_str("a password is needed"),
            Self::InvalidMac => {
                f.write_str("the MAC does not verify: wrong password or corrupted file")
            }
            Self::InvalidStore => f.write_str("invalid PKCS#12 store"),
            Self::NoCertificateChain => f.write_str("no certificate chain for the private key"),
            Self::AliasInUse => f.write_str("a key entry has the alias"),
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
