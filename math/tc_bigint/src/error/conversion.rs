use core::fmt;

/// Error returned by fixed-width conversions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversionError {
    /// The input does not fit in the destination precision.
    InputTooLarge,
    /// A negative value was supplied to an unsigned destination.
    NegativeValue,
    /// The caller-provided output buffer is too small.
    BufferTooSmall,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => output.write_str("input does not fit in the destination"),
            Self::NegativeValue => output.write_str("negative value is not unsigned"),
            Self::BufferTooSmall => output.write_str("output buffer is too small"),
        }
    }
}

impl core::error::Error for ConversionError {}

/// Error returned while parsing a textual integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseBigIntError {
    /// The radix is outside `2..=36`.
    InvalidRadix,
    /// The input is empty or contains a digit outside the radix.
    InvalidDigit,
    /// A negative value was supplied to an unsigned type.
    NegativeUnsigned,
    /// The value does not fit in a fixed-width destination.
    Overflow,
}

impl fmt::Display for ParseBigIntError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRadix => output.write_str("radix must be in 2..=36"),
            Self::InvalidDigit => output.write_str("invalid digit for radix"),
            Self::NegativeUnsigned => output.write_str("negative value is not unsigned"),
            Self::Overflow => output.write_str("value does not fit in the destination"),
        }
    }
}

impl core::error::Error for ParseBigIntError {}

#[cfg(test)]
mod tests {
    use super::{ConversionError, ParseBigIntError};
    use std::string::ToString;

    #[test]
    fn conversion_error_messages_are_stable() {
        assert_eq!(
            ConversionError::InputTooLarge.to_string(),
            "input does not fit in the destination"
        );
        assert_eq!(
            ConversionError::BufferTooSmall.to_string(),
            "output buffer is too small"
        );
        assert_eq!(
            ConversionError::NegativeValue.to_string(),
            "negative value is not unsigned"
        );
    }

    #[test]
    fn parse_error_messages_are_stable() {
        let cases = [
            (ParseBigIntError::InvalidRadix, "radix must be in 2..=36"),
            (ParseBigIntError::InvalidDigit, "invalid digit for radix"),
            (
                ParseBigIntError::NegativeUnsigned,
                "negative value is not unsigned",
            ),
            (
                ParseBigIntError::Overflow,
                "value does not fit in the destination",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }
}
