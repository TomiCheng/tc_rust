use core::fmt;

/// An agreement that BC's ECDH classes would refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdhError {
    /// An agreement was asked for before `init`.
    NotInitialized,
    /// The public key is on another domain than the private key.
    WrongDomain,
    /// The public key is infinity or not on the private key's curve.
    InvalidPublicKey,
    /// The cofactor has no inverse modulo n.
    InvalidCofactor,
    /// The shared point is infinity.
    InvalidAgreement,
    /// The output is shorter than the agreement.
    BufferTooSmall,
}

impl fmt::Display for EcdhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the agreement is not initialized",
            Self::WrongDomain => "the public key has another domain",
            Self::InvalidPublicKey => "the public key is not a valid point of the curve",
            Self::InvalidCofactor => "the cofactor is not invertible modulo the order",
            Self::InvalidAgreement => "the shared point is infinity",
            Self::BufferTooSmall => "the output buffer is too small",
        })
    }
}

impl core::error::Error for EcdhError {}
