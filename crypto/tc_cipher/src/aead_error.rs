//! Common AEAD processing errors.

use core::fmt;

/// A failure while processing or finalizing an AEAD operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadError {
    /// The cipher has not been initialized.
    NotInitialised,
    /// Associated data was supplied after message processing started.
    AadAfterData,
    /// Associated data exceeds the engine's fixed buffer capacity.
    AadTooLong { maximum: usize, actual: usize },
    /// The current operation has already been finalized.
    AlreadyFinalised,
    /// The output buffer is shorter than required.
    OutputTooShort { required: usize, available: usize },
    /// The ciphertext does not contain a complete authentication tag.
    CiphertextTooShort { minimum: usize, actual: usize },
    /// Authentication-tag verification failed.
    AuthenticationFailed,
    /// The algorithm's input-length limit would be exceeded.
    InputTooLong,
    /// A composed primitive failed despite validated internal invariants.
    InternalFailure,
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("AEAD cipher not initialised"),
            Self::AadAfterData => {
                f.write_str("associated data cannot be added after message processing starts")
            }
            Self::AadTooLong { maximum, actual } => write!(
                f,
                "associated data is too long: maximum {maximum} bytes, got {actual}"
            ),
            Self::AlreadyFinalised => f.write_str("AEAD operation already finalised"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::CiphertextTooShort { minimum, actual } => write!(
                f,
                "ciphertext is too short: requires at least {minimum} bytes, has {actual}"
            ),
            Self::AuthenticationFailed => f.write_str("authentication tag verification failed"),
            Self::InputTooLong => f.write_str("AEAD input length limit exceeded"),
            Self::InternalFailure => f.write_str("internal AEAD primitive failure"),
        }
    }
}

impl core::error::Error for AeadError {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::AeadError;

    #[test]
    fn aad_too_long_reports_both_lengths() {
        assert_eq!(
            format!(
                "{}",
                AeadError::AadTooLong {
                    maximum: 5,
                    actual: 6,
                }
            ),
            "associated data is too long: maximum 5 bytes, got 6"
        );
        assert_eq!(
            format!("{}", AeadError::InputTooLong),
            "AEAD input length limit exceeded"
        );
        assert_eq!(
            format!("{}", AeadError::InternalFailure),
            "internal AEAD primitive failure"
        );
    }
}
