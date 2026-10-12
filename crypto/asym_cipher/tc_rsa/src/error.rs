//! The errors of RSA.

/// What can go wrong in RSA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaError {
    /// The operation ran before it was initialized.
    NotInitialized,
    /// The public exponent to generate a key with is even or below three.
    InvalidPublicExponent,
    /// The modulus to generate is too small, or does not fit the integer
    /// types of the key.
    InvalidStrength,
    /// The certainty to test the primes to is zero.
    InvalidCertainty,
    /// The modulus of the key is zero.
    InvalidModulus,
    /// The modulus of the key is even.
    EvenModulus,
    /// The exponent of the key is zero.
    InvalidExponent,
    /// The exponent of a public key is even.
    EvenPublicExponent,
    /// The input is zero or one.
    InputTooSmall,
    /// The input is longer than the input block, or not below `n - 1`.
    InputTooLarge,
    /// The output is shorter than the output block.
    OutputTooShort,
}

/// The message of each error. Constant time.
impl core::fmt::Display for RsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "RSA operation not initialized",
            Self::InvalidPublicExponent => "RSA public exponent must be odd and at least 3",
            Self::InvalidStrength => "RSA key size too small or too large for the integer types",
            Self::InvalidCertainty => "RSA prime certainty must be at least 1",
            Self::InvalidModulus => "not a valid RSA modulus",
            Self::EvenModulus => "RSA modulus is even",
            Self::InvalidExponent => "not a valid RSA exponent",
            Self::EvenPublicExponent => "RSA public exponent is even",
            Self::InputTooSmall => "input too small for RSA cipher",
            Self::InputTooLarge => "input too large for RSA cipher",
            Self::OutputTooShort => "output buffer too short for RSA cipher",
        })
    }
}

impl core::error::Error for RsaError {}
