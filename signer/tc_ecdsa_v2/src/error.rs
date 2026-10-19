use core::fmt;

/// A signature that BC's `ECDsaSigner` would refuse to make or check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdsaError {
    /// A signature was asked for before `init`.
    NotInitialized,
    /// The key's curve has no order, or an even one.
    MissingOrder,
    /// The signer was initialized with a public key, and asked to sign.
    NotForSigning,
    /// The signer was initialized with a private key, and asked to verify.
    NotForVerifying,
}

impl fmt::Display for EcdsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the signer is not initialized",
            Self::MissingOrder => "the curve has no odd order",
            Self::NotForSigning => "signing requires a private key",
            Self::NotForVerifying => "verification requires a public key",
        })
    }
}

impl core::error::Error for EcdsaError {}
