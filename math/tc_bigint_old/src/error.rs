//! Error types returned by big-integer operations.

/// Error returned when parsing a [`crate::BigInt`] from a string fails.
///
/// Describes problems with the input string only; an out-of-range radix is a
/// caller error and panics instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseBigIntError {
    /// The input had no digits (empty string, or only a sign).
    Empty,
    /// A character was not a valid digit for the radix (invalid character, or
    /// a digit greater than or equal to the radix).
    InvalidDigit {
        /// Character index (into the original string) of the offending character.
        index: usize,
        /// The offending character.
        ch: char,
    },
}

impl core::fmt::Display for ParseBigIntError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseBigIntError::Empty => f.write_str("cannot parse integer from empty string"),
            ParseBigIntError::InvalidDigit { index, ch } => {
                write!(f, "invalid digit '{ch}' at position {index}")
            }
        }
    }
}

impl core::error::Error for ParseBigIntError {}

/// Error returned by the `try_to_bytes_*_into` methods when the destination
/// buffer is smaller than the encoding requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall {
    /// Number of bytes the encoding needs.
    pub needed: usize,
    /// Number of bytes the buffer provides.
    pub available: usize,
}

impl core::fmt::Display for BufferTooSmall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "buffer too small: need {} bytes, got {}",
            self.needed, self.available
        )
    }
}

impl core::error::Error for BufferTooSmall {}

/// Error returned when a [`crate::BigInt`] is out of range for the target
/// integer type in a `TryFrom`/`TryInto` conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryFromBigIntError(());

impl TryFromBigIntError {
    pub(crate) const fn new() -> Self {
        Self(())
    }
}

impl core::fmt::Display for TryFromBigIntError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("number out of range for the target integer type")
    }
}

impl core::error::Error for TryFromBigIntError {}
