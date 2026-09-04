//! Error types.

use core::fmt;

/// Error returned by fixed-width conversions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversionError {
    /// The input does not fit in the destination precision.
    InputTooLarge,
    /// The caller-provided output buffer is too small.
    BufferTooSmall,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => output.write_str("input does not fit in the destination"),
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

/// Errors returned by [`crate::RandomBits`] fallible constructors.
#[cfg(feature = "rand_core")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomBitsError<E> {
    /// The supplied random number generator failed.
    RandCore(E),
    /// A fixed-width integer was called with a different precision.
    BitsPrecisionMismatch {
        /// Requested precision in bits.
        bits_precision: u32,
        /// Precision required by the fixed-width integer type.
        integer_bits: u32,
    },
    /// The requested random value cannot fit in the requested precision.
    BitLengthTooLarge {
        /// Requested random value bit length.
        bit_length: u32,
        /// Available precision in bits.
        bits_precision: u32,
    },
}

#[cfg(feature = "rand_core")]
impl<E: fmt::Display> fmt::Display for RandomBitsError<E> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandCore(error) => error.fmt(output),
            Self::BitsPrecisionMismatch {
                bits_precision,
                integer_bits,
            } => write!(
                output,
                "requested precision {bits_precision} does not match integer precision {integer_bits}"
            ),
            Self::BitLengthTooLarge {
                bit_length,
                bits_precision,
            } => write!(
                output,
                "requested bit length {bit_length} exceeds precision {bits_precision}"
            ),
        }
    }
}

#[cfg(feature = "rand_core")]
impl<E> core::error::Error for RandomBitsError<E> where E: core::error::Error {}

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

    #[cfg(feature = "rand_core")]
    #[test]
    fn random_bits_error_messages_cover_every_variant() {
        use super::RandomBitsError;

        let rng_error: RandomBitsError<ConversionError> =
            RandomBitsError::RandCore(ConversionError::BufferTooSmall);
        assert_eq!(rng_error.to_string(), "output buffer is too small");

        let precision: RandomBitsError<ConversionError> = RandomBitsError::BitsPrecisionMismatch {
            bits_precision: 63,
            integer_bits: 64,
        };
        assert_eq!(
            precision.to_string(),
            "requested precision 63 does not match integer precision 64"
        );

        let length: RandomBitsError<ConversionError> = RandomBitsError::BitLengthTooLarge {
            bit_length: 65,
            bits_precision: 64,
        };
        assert_eq!(
            length.to_string(),
            "requested bit length 65 exceeds precision 64"
        );
    }
}
