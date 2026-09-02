//! Buffered-cipher processing error type.

use core::fmt;

/// Failures common to initialized buffered ciphers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BufferedError {
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
}

impl fmt::Display for BufferedError {
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
        }
    }
}

impl core::error::Error for BufferedError {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::BufferedError;

    #[test]
    fn displays_each_variant() {
        assert_eq!(
            format!("{}", BufferedError::NotInitialised),
            "buffered cipher not initialised"
        );
        assert_eq!(
            format!(
                "{}",
                BufferedError::OutputTooShort {
                    required: 16,
                    available: 8,
                }
            ),
            "output buffer is too short: requires 16 bytes, has 8"
        );
        assert_eq!(
            format!("{}", BufferedError::IncompleteLastBlock),
            "last block incomplete"
        );
        assert_eq!(
            format!("{}", BufferedError::CorruptPadding),
            "pad block corrupted"
        );
    }
}
