use core::error::Error;
use core::fmt;
use std::io;

use tc_algo_v2::AlgoError;
use tc_asn1::Asn1Error;

// The error of this crate, wrapping those of the crates underneath
#[derive(Debug)]
#[non_exhaustive]
pub enum X509Error {
    Algo(AlgoError),
    Asn1(Asn1Error),
    // Writing into a calculator failed; the error of its algorithm is inside
    Io(io::Error),
    // No row knows the key
    UnknownPublicKey,
    // A private key was given where a public one is needed
    NotPublicKey,
    // The encoding of a public key is not what its algorithm requires
    InvalidPublicKey,
    // A serial number must be a positive integer
    InvalidSerialNumber,
    // An extension with the same OID is already added
    DuplicateExtension,
    // The output buffer is shorter than the result
    OutputTooShort,
    // No row has the signature algorithm
    UnknownSigner,
    // A field a certificate needs is not set; the name of the field
    MissingField(&'static str),
    // The signature algorithm inside the TBS differs from the one outside it
    AlgorithmMismatch,
    // The signature does not verify with the key
    InvalidSignature,
}

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Algo(_) => f.write_str("algorithm failure"),
            Self::Asn1(_) => f.write_str("ASN.1 failure"),
            Self::Io(_) => f.write_str("calculator failure"),
            Self::UnknownPublicKey => f.write_str("unknown public key"),
            Self::NotPublicKey => f.write_str("a private key where a public key is needed"),
            Self::InvalidPublicKey => f.write_str("invalid public key encoding"),
            Self::InvalidSerialNumber => f.write_str("serial number must be a positive integer"),
            Self::DuplicateExtension => f.write_str("extension already added"),
            Self::OutputTooShort => f.write_str("output buffer too short"),
            Self::UnknownSigner => f.write_str("unknown signature algorithm"),
            Self::MissingField(field) => write!(f, "{field} is not set"),
            Self::AlgorithmMismatch => {
                f.write_str("signature algorithm in TBS differs from the outer one")
            }
            Self::InvalidSignature => f.write_str("signature does not verify"),
        }
    }
}

impl Error for X509Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Algo(error) => Some(error),
            Self::Asn1(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::UnknownPublicKey
            | Self::NotPublicKey
            | Self::InvalidPublicKey
            | Self::InvalidSerialNumber
            | Self::DuplicateExtension
            | Self::OutputTooShort
            | Self::UnknownSigner
            | Self::MissingField(_)
            | Self::AlgorithmMismatch
            | Self::InvalidSignature => None,
        }
    }
}

impl From<AlgoError> for X509Error {
    fn from(error: AlgoError) -> Self {
        Self::Algo(error)
    }
}

impl From<Asn1Error> for X509Error {
    fn from(error: Asn1Error) -> Self {
        Self::Asn1(error)
    }
}

impl From<io::Error> for X509Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
