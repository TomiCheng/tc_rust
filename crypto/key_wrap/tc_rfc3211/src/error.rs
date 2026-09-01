//! RFC 3211 operation and initialization errors.

use core::fmt;

/// A failure while wrapping or unwrapping key material with RFC 3211.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rfc3211Error<E> {
    /// A key-wrap operation was requested before initialization.
    NotInitialised,
    /// The engine was initialized for unwrapping, but wrapping was requested.
    NotForWrapping,
    /// The engine was initialized for wrapping, but unwrapping was requested.
    NotForUnwrapping,
    /// The input length is not valid for wrapping.
    InvalidWrapLength,
    /// The input length is not valid for unwrapping.
    InvalidUnwrapLength,
    /// The underlying cipher's block size cannot support RFC 3211.
    UnsupportedBlockSize {
        /// Actual block size in bytes.
        actual: usize,
        /// Minimum block size required by RFC 3211.
        minimum: usize,
    },
    /// The caller-provided output buffer is shorter than required.
    OutputTooShort {
        /// Required output capacity in bytes.
        required: usize,
        /// Available output capacity in bytes.
        available: usize,
    },
    /// The wrapped data failed its integrity check.
    IntegrityCheckFailed,
    /// The underlying block cipher reported a processing error.
    Cipher(E),
}

impl<E: core::error::Error> fmt::Display for Rfc3211Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("RFC 3211 wrapper not initialised"),
            Self::NotForWrapping => f.write_str("RFC 3211 wrapper not set for wrapping"),
            Self::NotForUnwrapping => f.write_str("RFC 3211 wrapper not set for unwrapping"),
            Self::InvalidWrapLength => f.write_str("invalid RFC 3211 wrap input length"),
            Self::InvalidUnwrapLength => f.write_str("invalid RFC 3211 unwrap input length"),
            Self::UnsupportedBlockSize { actual, minimum } => write!(
                f,
                "block size {actual} is too short; RFC 3211 requires at least {minimum} bytes"
            ),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::IntegrityCheckFailed => f.write_str("RFC 3211 integrity check failed"),
            Self::Cipher(error) => write!(f, "underlying block cipher error: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for Rfc3211Error<E> {}

/// A failure while initializing an RFC 3211 key wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rfc3211InitError<E> {
    /// The underlying cipher's block size cannot support RFC 3211.
    UnsupportedBlockSize {
        /// Actual block size in bytes.
        actual: usize,
        /// Minimum block size required by RFC 3211.
        minimum: usize,
    },
    /// The supplied IV length does not equal the cipher block size.
    InvalidIvLength {
        /// Actual IV length in bytes.
        actual: usize,
        /// Required IV length in bytes.
        required: usize,
    },
    /// The underlying block cipher reported an initialization error.
    Cipher(E),
}

impl<E: core::error::Error> fmt::Display for Rfc3211InitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedBlockSize { actual, minimum } => write!(
                f,
                "block size {actual} is too short; RFC 3211 requires at least {minimum} bytes"
            ),
            Self::InvalidIvLength { actual, required } => write!(
                f,
                "invalid RFC 3211 IV length: {actual} bytes; expected {required}"
            ),
            Self::Cipher(error) => {
                write!(f, "underlying block cipher initialization error: {error}")
            }
        }
    }
}

impl<E: core::error::Error> core::error::Error for Rfc3211InitError<E> {}
