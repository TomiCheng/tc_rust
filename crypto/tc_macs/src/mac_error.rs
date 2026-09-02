//! Common MAC processing and initialization errors.

use core::fmt;

/// A failure while processing or finalizing a message authentication code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacError {
    /// The MAC has not been initialized.
    NotInitialised,
    /// The output buffer is shorter than required.
    OutputTooShort { required: usize, available: usize },
}

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("MAC not initialised"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
        }
    }
}

impl core::error::Error for MacError {}

/// A failure while initializing a message authentication code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacInitError {
    /// The supplied key length was invalid, in bytes.
    InvalidKeyLength(usize),
}

impl fmt::Display for MacInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(bytes) => {
                write!(f, "invalid MAC key length: {bytes} bytes")
            }
        }
    }
}

impl core::error::Error for MacInitError {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::{MacError, MacInitError};

    #[test]
    fn operation_errors_report_required_lengths() {
        assert_eq!(
            format!("{}", MacError::NotInitialised),
            "MAC not initialised"
        );
        assert_eq!(
            format!(
                "{}",
                MacError::OutputTooShort {
                    required: 16,
                    available: 15,
                }
            ),
            "output buffer is too short: requires 16 bytes, has 15"
        );
    }

    #[test]
    fn initialization_errors_report_the_supplied_length() {
        assert_eq!(
            format!("{}", MacInitError::InvalidKeyLength(31)),
            "invalid MAC key length: 31 bytes"
        );
    }
}
