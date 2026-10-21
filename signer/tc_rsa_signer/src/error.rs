use core::fmt;

use tc_asn1::Asn1Error;
use tc_asym_encoding::EncodingError;

/// What can go wrong in an RSA signer. `E` is the error of the RSA engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaDigestSignerError<E> {
    /// The signer was used before `init`.
    NotInitialized,
    /// The signer was initialized with a public key, and asked to sign.
    NotForSigning,
    /// The signer was initialized with a private key, and asked to verify.
    NotForVerifying,
    /// The `DigestInfo` could not be DER encoded.
    Encoding(Asn1Error),
    /// The PKCS#1 encoding or the engine failed, such as a key too short for the `DigestInfo`.
    Cipher(EncodingError<E>),
}

impl<E: fmt::Display> fmt::Display for RsaDigestSignerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("the signer is not initialized"),
            Self::NotForSigning => f.write_str("signing requires a private key"),
            Self::NotForVerifying => f.write_str("verification requires a public key"),
            Self::Encoding(error) => write!(f, "unable to encode the DigestInfo: {error}"),
            Self::Cipher(error) => error.fmt(f),
        }
    }
}

impl<E: core::error::Error> core::error::Error for RsaDigestSignerError<E> {}
