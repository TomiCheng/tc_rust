use core::fmt;
use tc_binpoly::BinPolyError;

/// A parameter that a binary-field curve cannot take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum F2mError {
    /// The reduction polynomial was refused.
    Field(BinPolyError),
    /// An encoded element is not `⌈m / 8⌉` bytes long.
    InvalidLength { expected: usize, actual: usize },
    /// A coefficient or a coordinate has a bit at or above the degree `m`.
    NotReduced,
}

impl fmt::Display for F2mError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field(error) => write!(f, "invalid reduction polynomial: {error}"),
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            Self::NotReduced => f.write_str("a value has a bit at or above the degree"),
        }
    }
}

impl core::error::Error for F2mError {}
