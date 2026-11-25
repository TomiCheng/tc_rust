use core::fmt;

/// The error of an agreement with a KDF: `A` is the error of the agreement
/// underneath, `K` that of the KDF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgreementWithKdfError<A, K> {
    /// The agreement was used before `init` succeeded.
    NotInitialized,
    /// The output buffer is shorter than the derived key.
    BufferTooSmall,
    /// The agreement underneath failed.
    Agreement(A),
    /// The KDF failed.
    Kdf(K),
}

impl<A: fmt::Display, K: fmt::Display> fmt::Display for AgreementWithKdfError<A, K> {
    /// Writes the message; a wrapped error keeps its own. Constant time, apart
    /// from the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("Agreement algorithm not initialised"),
            Self::BufferTooSmall => f.write_str("the output buffer is too small"),
            Self::Agreement(error) => error.fmt(f),
            Self::Kdf(error) => error.fmt(f),
        }
    }
}

impl<A: core::error::Error, K: core::error::Error> core::error::Error
    for AgreementWithKdfError<A, K>
{
}
