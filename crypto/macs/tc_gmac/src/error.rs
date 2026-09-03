//! GMAC construction errors.

use core::fmt;

/// A failure while constructing a GMAC instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateError {
    /// GCM requires a 16-byte block cipher.
    InvalidBlockSize(usize),
    /// GMAC supports tags from 4 through 16 bytes.
    InvalidMacSize(usize),
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize(bytes) => {
                write!(f, "GMAC requires a 16-byte block cipher, got {bytes}")
            }
            Self::InvalidMacSize(bytes) => {
                write!(f, "invalid GMAC authentication-tag size: {bytes} bytes")
            }
        }
    }
}

impl core::error::Error for CreateError {}
