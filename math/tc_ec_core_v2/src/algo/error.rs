/// Failure in a shared elliptic-curve algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlgorithmError {
    /// Point and scalar slices must have the same nonzero length.
    InvalidLength,
    /// The points belong to different curve equations or fields.
    CurveMismatch,
    /// A point fails equation or subgroup validation.
    InvalidPoint,
    /// A batch product (or the optional scale) is not invertible.
    NotInvertible,
    /// A scalar exceeds the public capacity of a precomputed table.
    ScalarTooLarge,
}

impl core::fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "invalid point/scalar lengths",
            Self::CurveMismatch => "different curves",
            Self::InvalidPoint => "invalid point",
            Self::NotInvertible => "noninvertible batch product",
            Self::ScalarTooLarge => "scalar exceeds table capacity",
        })
    }
}
impl core::error::Error for AlgorithmError {}