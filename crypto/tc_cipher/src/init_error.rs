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
    /// The supplied tweak length was invalid, in bytes.
    InvalidTweakLength(usize),
    /// The supplied initialization-vector length was invalid, in bytes.
    InvalidIvLength(usize),
    /// The supplied round count was invalid.
    InvalidRounds(usize),
    /// Initial associated data exceeds the engine's fixed buffer capacity.
    InitialAadTooLong { maximum: usize, actual: usize },
    /// The same key and nonce would be reused for encryption.
    NonceReuse,
    /// A composed primitive failed despite validated internal invariants.
    InternalFailure,
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
            Self::InvalidTweakLength(bytes) => {
                write!(f, "invalid cipher tweak length: {bytes} bytes")
            }
            Self::InvalidIvLength(bytes) => {
                write!(f, "invalid cipher IV length: {bytes} bytes")
            }
            Self::InvalidRounds(rounds) => {
                write!(f, "invalid cipher round count: {rounds}")
            }
            Self::InitialAadTooLong { maximum, actual } => write!(
                f,
                "initial AAD is too long: maximum {maximum} bytes, got {actual}"
            ),
            Self::NonceReuse => f.write_str("key and nonce cannot be reused for AEAD encryption"),
            Self::InternalFailure => f.write_str("internal cipher primitive failure"),
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
        assert_eq!(
            format!("{}", InitError::InvalidTweakLength(8)),
            "invalid cipher tweak length: 8 bytes"
        );
        assert_eq!(
            format!("{}", InitError::InvalidIvLength(7)),
            "invalid cipher IV length: 7 bytes"
        );
        assert_eq!(
            format!("{}", InitError::InvalidRounds(256)),
            "invalid cipher round count: 256"
        );
        assert_eq!(
            format!(
                "{}",
                InitError::InitialAadTooLong {
                    maximum: 3,
                    actual: 4,
                }
            ),
            "initial AAD is too long: maximum 3 bytes, got 4"
        );
        assert_eq!(
            format!("{}", InitError::NonceReuse),
            "key and nonce cannot be reused for AEAD encryption"
        );
        assert_eq!(
            format!("{}", InitError::InternalFailure),
            "internal cipher primitive failure"
        );
    }
}
