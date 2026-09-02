//! Common padding error type.

use core::fmt;

/// A failure while adding or removing block padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaddingError {
    /// The scheme was used before a successful call to
    /// [`BlockCipherPaddingInit::init`](crate::BlockCipherPaddingInit::init).
    NotInitialised,
    /// The requested padding position lies past the end of the block.
    PositionOutOfRange,
    /// The trailing bytes of the block are not a valid encoding for the scheme.
    ///
    /// Self-describing schemes such as PKCS#7 report this; schemes that encode
    /// no length, such as zero-byte padding, cannot detect corruption at all.
    CorruptPadding,
}

impl fmt::Display for PaddingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("padding not initialised"),
            Self::PositionOutOfRange => {
                f.write_str("padding position is past the end of the block")
            }
            Self::CorruptPadding => f.write_str("pad block corrupted"),
        }
    }
}

impl core::error::Error for PaddingError {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::PaddingError;

    #[test]
    fn displays_each_variant() {
        assert_eq!(
            format!("{}", PaddingError::NotInitialised),
            "padding not initialised"
        );
        assert_eq!(
            format!("{}", PaddingError::PositionOutOfRange),
            "padding position is past the end of the block"
        );
        assert_eq!(
            format!("{}", PaddingError::CorruptPadding),
            "pad block corrupted"
        );
    }
}
