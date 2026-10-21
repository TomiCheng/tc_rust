use core::fmt;

/// A coordinate that a SEC prime curve cannot take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecPError {
    /// An encoded element is not the field's length.
    InvalidLength { expected: usize, actual: usize },
    /// A coordinate is not below p.
    NotBelowModulus,
}

impl fmt::Display for SecPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            Self::NotBelowModulus => f.write_str("a value is not below the modulus"),
        }
    }
}

impl core::error::Error for SecPError {}
