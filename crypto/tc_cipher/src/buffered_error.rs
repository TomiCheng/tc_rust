//! Buffered-cipher processing error type.

use core::convert::Infallible;
use core::fmt;

/// Failures common to initialized buffered ciphers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BufferedError<E = Infallible> {
    /// Processing was requested before successful initialization.
    NotInitialised,
    /// The output buffer is shorter than required.
    OutputTooShort { required: usize, available: usize },
    /// Finalization found a trailing partial block it cannot resolve.
    ///
    /// Decrypting a padded message requires a whole number of blocks, and an
    /// unpadded mode that rejects partial blocks requires the same.
    IncompleteLastBlock,
    /// The padding on the final block was rejected.
    ///
    /// Callers must not report this separately from an authentication failure:
    /// distinguishing the two is what a padding oracle needs.
    CorruptPadding,
    /// The wrapped block cipher failed while processing a block.
    Cipher(E),
}

impl<E: fmt::Display> fmt::Display for BufferedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("buffered cipher not initialised"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::IncompleteLastBlock => f.write_str("last block incomplete"),
            Self::CorruptPadding => f.write_str("pad block corrupted"),
            Self::Cipher(error) => write!(f, "underlying cipher failed: {error}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for BufferedError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Cipher(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    extern crate std;

    use std::format;

    use super::BufferedError;
    use crate::BlockError;

    type CommonError = BufferedError<Infallible>;

    #[test]
    fn displays_each_variant() {
        assert_eq!(
            format!("{}", CommonError::NotInitialised),
            "buffered cipher not initialised"
        );
        assert_eq!(
            format!(
                "{}",
                CommonError::OutputTooShort {
                    required: 16,
                    available: 8,
                }
            ),
            "output buffer is too short: requires 16 bytes, has 8"
        );
        assert_eq!(
            format!("{}", CommonError::IncompleteLastBlock),
            "last block incomplete"
        );
        assert_eq!(
            format!("{}", CommonError::CorruptPadding),
            "pad block corrupted"
        );
        assert_eq!(
            format!("{}", BufferedError::Cipher(BlockError::NotInitialised)),
            "underlying cipher failed: block cipher not initialised"
        );
    }
}
