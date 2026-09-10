use core::fmt;

/// Errors returned by [`crate::RandomBits`] fallible constructors.
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

impl<E> core::error::Error for RandomBitsError<E> where E: core::error::Error {}

#[cfg(test)]
mod tests {
    use crate::ConversionError;
    use std::string::ToString;

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
