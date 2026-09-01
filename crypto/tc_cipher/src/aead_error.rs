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
    /// The current operation has already been finalized.
    AlreadyFinalised,
    /// The output buffer is shorter than required.
    OutputTooShort { required: usize, available: usize },
    /// The ciphertext does not contain a complete authentication tag.
    CiphertextTooShort { minimum: usize, actual: usize },
    /// Authentication-tag verification failed.
    AuthenticationFailed,
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("AEAD cipher not initialised"),
            Self::AadAfterData => {
                f.write_str("associated data cannot be added after message processing starts")
            }
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
        }
    }
}

impl core::error::Error for AeadError {}
