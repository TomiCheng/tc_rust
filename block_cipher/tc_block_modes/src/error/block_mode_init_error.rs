//! Block-cipher-mode initialization error type.

use core::fmt;

/// A failure while initializing a block-cipher mode.
///
/// `E` is the initialization error reported by the underlying block cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockModeInitError<E> {
    /// The supplied initialization-vector length was invalid, in bytes.
    InvalidIvLength(usize),
    /// The supplied feedback size was invalid, in bits.
    InvalidFeedbackSize(usize),
    /// The underlying block size is not supported by the mode.
    UnsupportedBlockSize {
        /// The underlying cipher's block size, in bytes.
        actual: usize,
        /// The block size required by the mode, in bytes.
        required: usize,
    },
    /// The underlying block cipher reported an initialization error.
    Cipher(E),
}

impl<E: core::error::Error> fmt::Display for BlockModeInitError<E> {
    /// Writes a description, including the engine's error for `Cipher`.
    /// Constant time: errors carry no secret data; output timing depends on
    /// the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIvLength(bytes) => {
                write!(f, "invalid block cipher mode IV length: {bytes} bytes")
            }
            Self::InvalidFeedbackSize(bits) => {
                write!(f, "invalid block cipher mode feedback size: {bits} bits")
            }
            Self::UnsupportedBlockSize { actual, required } => write!(
                f,
                "unsupported block size: {actual} bytes; mode requires {required} bytes"
            ),
            Self::Cipher(error) => {
                write!(f, "underlying block cipher initialization error: {error}")
            }
        }
    }
}

impl<E: core::error::Error> core::error::Error for BlockModeInitError<E> {}
