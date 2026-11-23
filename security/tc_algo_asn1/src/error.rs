use core::error::Error;
use core::fmt;

use tc_algo::AlgoError;
use tc_asn1::Asn1Error;

#[derive(Debug)]
#[non_exhaustive]
pub enum AlgoAsn1Error {
    Asn1(Asn1Error),
    // A failure of tc_algo, such as signing with a key of another algorithm
    Algo(AlgoError),
    // No row knows the public key or its algorithm
    UnknownPublicKey,
    // A private key was given where a public one is needed
    NotPublicKey,
    // The encoding of a public key is not what its algorithm requires
    InvalidPublicKey,
    // No row knows the private key or its algorithm
    UnknownPrivateKey,
    // A public key was given where a private one is needed
    NotPrivateKey,
    // The encoding of a private key is not what its algorithm requires
    InvalidPrivateKey,
    // No row has the signature algorithm
    UnknownSigner,
}

impl fmt::Display for AlgoAsn1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(_) => f.write_str("ASN.1 failure"),
            Self::Algo(_) => f.write_str("algorithm failure"),
            Self::UnknownPublicKey => f.write_str("unknown public key"),
            Self::NotPublicKey => f.write_str("a private key where a public key is needed"),
            Self::InvalidPublicKey => f.write_str("invalid public key encoding"),
            Self::UnknownPrivateKey => f.write_str("unknown private key"),
            Self::NotPrivateKey => f.write_str("a public key where a private key is needed"),
            Self::InvalidPrivateKey => f.write_str("invalid private key encoding"),
            Self::UnknownSigner => f.write_str("unknown signature algorithm"),
        }
    }
}

impl Error for AlgoAsn1Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Asn1(error) => Some(error),
            Self::Algo(error) => Some(error),
            Self::UnknownPublicKey
            | Self::NotPublicKey
            | Self::InvalidPublicKey
            | Self::UnknownPrivateKey
            | Self::NotPrivateKey
            | Self::InvalidPrivateKey
            | Self::UnknownSigner => None,
        }
    }
}

impl From<Asn1Error> for AlgoAsn1Error {
    fn from(error: Asn1Error) -> Self {
        Self::Asn1(error)
    }
}

impl From<AlgoError> for AlgoAsn1Error {
    fn from(error: AlgoError) -> Self {
        Self::Algo(error)
    }
}
