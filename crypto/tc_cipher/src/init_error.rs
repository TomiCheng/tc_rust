//! Cipher-initialization error type.

use core::fmt;

/// Failures common to cipher initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitError {
    /// The supplied key length was invalid, in bytes.
    InvalidKeyLength(usize),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(bytes) => {
                write!(f, "invalid cipher key length: {bytes} bytes")
            }
        }
    }
}

impl core::error::Error for InitError {}
