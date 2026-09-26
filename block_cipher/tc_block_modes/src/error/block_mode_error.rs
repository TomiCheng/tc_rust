//! Block-cipher-mode processing error type.

use core::fmt;

/// A failure while processing data through a block-cipher mode.
///
/// `E` is the processing error reported by the underlying block cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockModeError<E> {
    /// A block was processed before the mode was successfully initialized.
    NotInitialised,
    /// The input or output buffer could not hold the required data.
    BufferTooShort,
    /// The underlying block cipher reported an error.
    Cipher(E),
}

impl<E: core::error::Error> fmt::Display for BlockModeError<E> {
    /// Writes a description, including the engine's error for `Cipher`.
    /// Constant time: errors carry no secret data; output timing depends on
    /// the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("block cipher mode not initialised"),
            Self::BufferTooShort => {
                f.write_str("input or output buffer too short for block cipher mode")
            }
            Self::Cipher(error) => write!(f, "underlying block cipher error: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for BlockModeError<E> {}
