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
    /// The supplied round count was invalid.
    InvalidRounds(usize),
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
            Self::InvalidRounds(rounds) => {
                write!(f, "invalid cipher round count: {rounds}")
            }
        }
    }
}

impl core::error::Error for InitError {}
