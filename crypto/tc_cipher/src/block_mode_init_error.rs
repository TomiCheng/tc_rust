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

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::BlockModeInitError;
    use crate::InitError;

    #[test]
    fn reports_mode_and_underlying_cipher_errors() {
        assert_eq!(
            format!("{}", BlockModeInitError::<InitError>::InvalidIvLength(7)),
            "invalid block cipher mode IV length: 7 bytes"
        );
        assert_eq!(
            format!(
                "{}",
                BlockModeInitError::<InitError>::InvalidFeedbackSize(7)
            ),
            "invalid block cipher mode feedback size: 7 bits"
        );
        assert_eq!(
            format!(
                "{}",
                BlockModeInitError::<InitError>::UnsupportedBlockSize {
                    actual: 8,
                    required: 16,
                }
            ),
            "unsupported block size: 8 bytes; mode requires 16 bytes"
        );
        assert_eq!(
            format!(
                "{}",
                BlockModeInitError::Cipher(InitError::InvalidKeyLength(7))
            ),
            "underlying block cipher initialization error: invalid cipher key length: 7 bytes"
        );
    }
}
