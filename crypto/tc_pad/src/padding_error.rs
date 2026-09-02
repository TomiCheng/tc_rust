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
    /// The block is longer than the scheme's length encoding can describe.
    ///
    /// PKCS#7, ANSI X9.23, and ISO 10126-2 record the padding count in a single
    /// byte and therefore cannot serve blocks of 256 bytes or more.
    UnsupportedBlockSize,
    /// The block is already full, leaving no room for padding.
    ///
    /// Schemes that must write at least one byte, such as PKCS#7 and
    /// ISO 7816-4, report this when the padding position equals the block
    /// length. Schemes that can add nothing at all, such as zero-byte padding,
    /// return a count of zero instead.
    BlockFull,
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
            Self::UnsupportedBlockSize => {
                f.write_str("block is too long for a single-byte padding count")
            }
            Self::BlockFull => f.write_str("block leaves no room for padding"),
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
            format!("{}", PaddingError::UnsupportedBlockSize),
            "block is too long for a single-byte padding count"
        );
        assert_eq!(
            format!("{}", PaddingError::BlockFull),
            "block leaves no room for padding"
        );
        assert_eq!(
            format!("{}", PaddingError::CorruptPadding),
            "pad block corrupted"
        );
    }
}
