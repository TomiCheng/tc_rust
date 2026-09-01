//! Cipher-initialization error type.

use core::fmt;

/// Failures common to cipher initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitError {
    /// The supplied key length was invalid, in bytes.
    InvalidKeyLength(usize),
    /// The supplied effective key size was invalid, in bits.
    InvalidEffectiveKeyBits(usize),
    /// The supplied S-box length was invalid, in bytes.
    InvalidSBoxLength(usize),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(bytes) => {
                write!(f, "invalid cipher key length: {bytes} bytes")
            }
            Self::InvalidEffectiveKeyBits(bits) => {
                write!(f, "invalid effective cipher key size: {bits} bits")
            }
            Self::InvalidSBoxLength(bytes) => {
                write!(f, "invalid cipher s-box length: {bytes} bytes")
            }
        }
    }
}

impl core::error::Error for InitError {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::InitError;

    #[test]
    fn each_variant_reports_the_offending_length() {
        assert_eq!(
            format!("{}", InitError::InvalidKeyLength(7)),
            "invalid cipher key length: 7 bytes"
        );
        assert_eq!(
            format!("{}", InitError::InvalidEffectiveKeyBits(0)),
            "invalid effective cipher key size: 0 bits"
        );
        assert_eq!(
            format!("{}", InitError::InvalidSBoxLength(127)),
            "invalid cipher s-box length: 127 bytes"
        );
    }
}
