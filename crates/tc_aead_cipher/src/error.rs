//! Common AEAD-cipher errors.

use core::fmt;

/// Errors shared by AEAD-cipher initialization and processing operations.
///
/// More variants may be added as engines are implemented; downstream matches
/// must include a wildcard arm.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadCipherError {
    /// The supplied key length is unsupported.
    InvalidKeyLength(usize),
    /// The supplied nonce length does not match the required length.
    InvalidNonceLength {
        /// Required nonce length in bytes.
        expected: usize,
        /// Supplied nonce length in bytes.
        actual: usize,
    },
    /// The supplied AAD length does not match the length declared at init.
    AadLengthMismatch {
        /// Declared total AAD length in bytes.
        expected: usize,
        /// Supplied or attempted total AAD length in bytes.
        actual: usize,
    },
    /// The cipher has not been initialized with a key and nonce.
    NotInitialised,
    /// Associated data was supplied after message processing had started.
    AadAfterData,
    /// The current operation has already been finalized.
    AlreadyFinalised,
    /// The caller-provided output buffer cannot hold the next output.
    OutputBufferTooShort {
        /// Required output capacity in bytes.
        required: usize,
        /// Supplied output capacity in bytes.
        actual: usize,
    },
    /// The ciphertext does not contain a complete authentication tag.
    CiphertextTooShort {
        /// Minimum ciphertext length in bytes.
        minimum: usize,
        /// Supplied ciphertext length in bytes.
        actual: usize,
    },
    /// Authentication-tag verification failed.
    AuthenticationFailed,
}

impl fmt::Display for AeadCipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(actual) => {
                write!(f, "key length {actual} bytes is unsupported")
            }
            Self::InvalidNonceLength { expected, actual } => write!(
                f,
                "nonce length {actual} bytes does not match the required {expected} bytes"
            ),
            Self::AadLengthMismatch { expected, actual } => write!(
                f,
                "AAD length {actual} bytes does not match the declared {expected} bytes"
            ),
            Self::NotInitialised => f.write_str("AEAD cipher is not initialised"),
            Self::AadAfterData => {
                f.write_str("associated data cannot be added after message processing starts")
            }
            Self::AlreadyFinalised => f.write_str("AEAD operation is already finalised"),
            Self::OutputBufferTooShort { required, actual } => write!(
                f,
                "output buffer is too short: need {required} bytes, got {actual}"
            ),
            Self::CiphertextTooShort { minimum, actual } => write!(
                f,
                "ciphertext is too short: need at least {minimum} bytes, got {actual}"
            ),
            Self::AuthenticationFailed => f.write_str("authentication tag verification failed"),
        }
    }
}

impl core::error::Error for AeadCipherError {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::ToString;

    use super::AeadCipherError;

    fn assert_error<T: core::error::Error>() {}

    #[test]
    fn implements_core_error() {
        assert_error::<AeadCipherError>();
    }

    #[test]
    fn formats_parameter_errors() {
        assert_eq!(
            AeadCipherError::InvalidKeyLength(15).to_string(),
            "key length 15 bytes is unsupported"
        );
        assert_eq!(
            AeadCipherError::InvalidNonceLength {
                expected: 16,
                actual: 15,
            }
            .to_string(),
            "nonce length 15 bytes does not match the required 16 bytes"
        );
        assert_eq!(
            AeadCipherError::OutputBufferTooShort {
                required: 16,
                actual: 15,
            }
            .to_string(),
            "output buffer is too short: need 16 bytes, got 15"
        );
        assert_eq!(
            AeadCipherError::AadLengthMismatch {
                expected: 7,
                actual: 6,
            }
            .to_string(),
            "AAD length 6 bytes does not match the declared 7 bytes"
        );
        assert_eq!(
            AeadCipherError::AuthenticationFailed.to_string(),
            "authentication tag verification failed"
        );
    }
}
