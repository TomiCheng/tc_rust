use core::fmt;

/// A parameter that a prime-field curve cannot take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FpError {
    /// The modulus is even; Montgomery arithmetic needs an odd one.
    EvenModulus,
    /// A coefficient or a coordinate is not below the modulus.
    NotBelowModulus,
}

impl fmt::Display for FpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EvenModulus => "the modulus is even",
            Self::NotBelowModulus => "a value is not below the modulus",
        })
    }
}

impl core::error::Error for FpError {}
