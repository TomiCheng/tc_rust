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
    // No row has the digest algorithm
    UnknownDigest,
    // No row has the MAC algorithm
    UnknownMac,
    // No row has the cipher
    UnknownCipher,
    // The parameters of a cipher are not what its row writes, or a cipher by name was asked to
    // decrypt, with no parameters read to decrypt with
    InvalidCipherParameters,
    // The key is not a KeyOwned of the size the cipher takes
    InvalidKey,
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
            Self::UnknownDigest => f.write_str("unknown digest algorithm"),
            Self::UnknownMac => f.write_str("unknown MAC algorithm"),
            Self::UnknownCipher => f.write_str("unknown cipher"),
            Self::InvalidCipherParameters => f.write_str("invalid cipher parameters"),
            Self::InvalidKey => f.write_str("invalid key for the cipher"),
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
            | Self::UnknownSigner
            | Self::UnknownDigest
            | Self::UnknownMac
            | Self::UnknownCipher
            | Self::InvalidCipherParameters
            | Self::InvalidKey => None,
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
