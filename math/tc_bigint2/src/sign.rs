//! Sign representation for arbitrary-precision signed integers.

/// The sign of an arbitrary-precision integer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Sign {
    /// A negative value.
    Negative,
    /// Zero.
    #[default]
    Zero,
    /// A positive value.
    Positive,
}
