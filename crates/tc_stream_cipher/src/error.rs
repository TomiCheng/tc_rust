//! Common stream-cipher errors.

/// Errors shared by stream-cipher initialization and processing operations.
///
/// More variants may be added as additional stream ciphers are implemented;
/// downstream matches must include a wildcard arm.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamCipherError {
    /// The requested round count is unsupported.
    InvalidRounds(usize),
    /// The supplied key length is unsupported.
    InvalidKeyLength(usize),
    /// The supplied initialization-vector length is unsupported.
    InvalidIvLength(usize),
    /// The supplied nonce length does not match the required length.
    InvalidNonceLength {
        /// Required nonce length in bytes.
        expected: usize,
        /// Supplied nonce length in bytes.
        actual: usize,
    },
    /// A data method was called before the cipher was initialized.
    NotInitialised,
    /// The output buffer is shorter than the input.
    OutputBufferTooShort,
    /// The maximum amount of data permitted for the current key and nonce was exceeded.
    MaxBytesExceeded,
    /// The cipher's block counter cannot be advanced further.
    CounterExhausted,
}

impl core::fmt::Display for StreamCipherError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidRounds(rounds) => write!(f, "round count {rounds} is unsupported"),
            Self::InvalidKeyLength(actual) => {
                write!(f, "key length {actual} bytes is unsupported")
            }
            Self::InvalidIvLength(actual) => {
                write!(f, "IV length {actual} bytes is unsupported")
            }
            Self::InvalidNonceLength { expected, actual } => {
                write!(
                    f,
                    "nonce length {actual} bytes does not match the required {expected} bytes"
                )
            }
            Self::NotInitialised => f.write_str("stream cipher is not initialised"),
            Self::OutputBufferTooShort => f.write_str("output buffer is shorter than input"),
            Self::MaxBytesExceeded => {
                f.write_str("maximum bytes per key and nonce would be exceeded")
            }
            Self::CounterExhausted => f.write_str("stream cipher counter is exhausted"),
        }
    }
}

impl core::error::Error for StreamCipherError {}

#[cfg(test)]
mod tests {
    use super::StreamCipherError;

    fn assert_error<T: core::error::Error>() {}

    #[test]
    fn implements_core_error() {
        assert_error::<StreamCipherError>();
    }

    #[test]
    fn formats_every_variant() {
        let cases = [
            StreamCipherError::InvalidRounds(3),
            StreamCipherError::InvalidKeyLength(7),
            StreamCipherError::InvalidIvLength(8),
            StreamCipherError::InvalidNonceLength {
                expected: 12,
                actual: 8,
            },
            StreamCipherError::NotInitialised,
            StreamCipherError::OutputBufferTooShort,
            StreamCipherError::MaxBytesExceeded,
            StreamCipherError::CounterExhausted,
        ];

        for error in cases {
            assert!(!error.to_string().is_empty());
        }
    }
}
