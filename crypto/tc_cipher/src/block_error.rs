//! Block-processing error type.

use core::fmt;

/// Failures common to initialized block ciphers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockError {
    /// Block processing was requested before successful initialization.
    NotInitialised,
    /// The input or output buffer could not hold one complete block.
    BufferTooShort,
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("block cipher not initialised"),
            Self::BufferTooShort => f.write_str("input or output buffer too short for one block"),
        }
    }
}

impl core::error::Error for BlockError {}
