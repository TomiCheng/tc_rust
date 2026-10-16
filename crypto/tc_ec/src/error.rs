use core::fmt;

/// A key or a domain that BC's EC parameter classes would refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcError {
    /// A key pair was asked for before `init`.
    NotInitialized,
    /// The curve has no order n, which keys need.
    MissingOrder,
    /// The generator G is infinity, off its curve or outside the subgroup.
    InvalidGenerator,
    /// The private scalar d is not in `[1, n - 1]`.
    InvalidPrivateScalar,
    /// The public point Q is infinity, on another curve, off the curve or outside the
    /// subgroup.
    InvalidPublicPoint,
}

impl fmt::Display for EcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the key-pair generator is not initialized",
            Self::MissingOrder => "the curve has no order",
            Self::InvalidGenerator => "the generator is not a valid point of the subgroup",
            Self::InvalidPrivateScalar => "the private scalar is not in [1, n - 1]",
            Self::InvalidPublicPoint => "the public point is not a valid point of the subgroup",
        })
    }
}

impl core::error::Error for EcError {}
