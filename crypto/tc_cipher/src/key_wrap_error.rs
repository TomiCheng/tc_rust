//! Shared key-wrap operation and initialization errors.

use core::fmt;

/// A failure while wrapping or unwrapping key material.
///
/// `E` is the processing error reported by the underlying cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyWrapError<E> {
    /// A key-wrap operation was requested before successful initialization.
    NotInitialised,
    /// The engine was initialized for unwrapping, but wrapping was requested.
    NotForWrapping,
    /// The engine was initialized for wrapping, but unwrapping was requested.
    NotForUnwrapping,
    /// The wrap input length is invalid for the selected algorithm.
    InvalidWrapLength,
    /// The unwrap input length is invalid for the selected algorithm.
    InvalidUnwrapLength,
    /// The underlying cipher's block size is not supported.
    UnsupportedBlockSize {
        /// The underlying cipher's block size, in bytes.
        actual: usize,
        /// The block size required by the wrapper, in bytes.
        required: usize,
    },
    /// The underlying cipher's block size is shorter than the wrapper permits.
    BlockSizeTooShort {
        /// The underlying cipher's block size, in bytes.
        actual: usize,
        /// The minimum block size accepted by the wrapper, in bytes.
        minimum: usize,
    },
    /// The output buffer is shorter than required.
    OutputTooShort {
        /// Required output capacity in bytes.
        required: usize,
        /// Available output capacity in bytes.
        available: usize,
    },
    /// The wrapped data failed its integrity validation.
    IntegrityCheckFailed,
    /// The underlying cipher reported a processing error.
    Cipher(E),
}

impl<E: core::error::Error> fmt::Display for KeyWrapError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("key wrapper not initialised"),
            Self::NotForWrapping => f.write_str("key wrapper not set for wrapping"),
            Self::NotForUnwrapping => f.write_str("key wrapper not set for unwrapping"),
            Self::InvalidWrapLength => f.write_str("invalid key-wrap input length"),
            Self::InvalidUnwrapLength => f.write_str("invalid key-unwrap input length"),
            Self::UnsupportedBlockSize { actual, required } => write!(
                f,
                "unsupported block size: {actual} bytes; key wrapper requires {required} bytes"
            ),
            Self::BlockSizeTooShort { actual, minimum } => write!(
                f,
                "block size {actual} is too short; key wrapper requires at least {minimum} bytes"
            ),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::IntegrityCheckFailed => f.write_str("key-wrap integrity check failed"),
            Self::Cipher(error) => write!(f, "underlying cipher error: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for KeyWrapError<E> {}

/// A failure while initializing a key wrapper.
///
/// `E` is the initialization error reported by the underlying cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyWrapInitError<E> {
    /// A custom IV was supplied while initializing for unwrap.
    IvNotAllowedForUnwrap,
    /// The supplied initialization-vector length is not supported.
    InvalidIvLength {
        /// Supplied IV length, in bytes.
        actual: usize,
        /// IV length required by the wrapper, in bytes.
        required: usize,
    },
    /// The underlying cipher's block size is not supported.
    UnsupportedBlockSize {
        /// The underlying cipher's block size, in bytes.
        actual: usize,
        /// The block size required by the wrapper, in bytes.
        required: usize,
    },
    /// The underlying cipher's block size is shorter than the wrapper permits.
    BlockSizeTooShort {
        /// The underlying cipher's block size, in bytes.
        actual: usize,
        /// The minimum block size accepted by the wrapper, in bytes.
        minimum: usize,
    },
    /// The underlying cipher reported an initialization error.
    Cipher(E),
}

impl<E: core::error::Error> fmt::Display for KeyWrapInitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IvNotAllowedForUnwrap => {
                f.write_str("an external IV is not allowed when unwrapping")
            }
            Self::InvalidIvLength { actual, required } => write!(
                f,
                "invalid key-wrap IV length: {actual} bytes; expected {required}"
            ),
            Self::UnsupportedBlockSize { actual, required } => write!(
                f,
                "unsupported block size: {actual} bytes; key wrapper requires {required} bytes"
            ),
            Self::BlockSizeTooShort { actual, minimum } => write!(
                f,
                "block size {actual} is too short; key wrapper requires at least {minimum} bytes"
            ),
            Self::Cipher(error) => write!(f, "underlying cipher initialization error: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for KeyWrapInitError<E> {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::{KeyWrapError, KeyWrapInitError};
    use crate::{BlockError, InitError};

    #[test]
    fn reports_operation_errors() {
        assert_eq!(
            format!("{}", KeyWrapError::<BlockError>::InvalidWrapLength),
            "invalid key-wrap input length"
        );
        assert_eq!(
            format!(
                "{}",
                KeyWrapError::<BlockError>::UnsupportedBlockSize {
                    actual: 8,
                    required: 16,
                }
            ),
            "unsupported block size: 8 bytes; key wrapper requires 16 bytes"
        );
        assert_eq!(
            format!("{}", KeyWrapError::Cipher(BlockError::BufferTooShort)),
            "underlying cipher error: input or output buffer too short for one block"
        );
    }

    #[test]
    fn reports_initialization_errors() {
        assert_eq!(
            format!(
                "{}",
                KeyWrapInitError::<InitError>::InvalidIvLength {
                    actual: 4,
                    required: 8,
                }
            ),
            "invalid key-wrap IV length: 4 bytes; expected 8"
        );
        assert_eq!(
            format!(
                "{}",
                KeyWrapInitError::Cipher(InitError::InvalidKeyLength(7))
            ),
            "underlying cipher initialization error: invalid cipher key length: 7 bytes"
        );
    }
}
