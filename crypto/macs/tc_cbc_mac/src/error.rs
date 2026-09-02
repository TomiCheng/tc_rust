use core::fmt;

/// A failure while constructing CBC-MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateError {
    InvalidBlockSize(usize),
    InvalidMacSize {
        requested_bits: usize,
        maximum_bits: usize,
    },
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize(bytes) => write!(f, "invalid CBC-MAC block size: {bytes} bytes"),
            Self::InvalidMacSize {
                requested_bits,
                maximum_bits,
            } => write!(
                f,
                "invalid CBC-MAC size: requested {requested_bits} bits, maximum {maximum_bits} bits"
            ),
        }
    }
}

impl core::error::Error for CreateError {}

/// A CBC-MAC processing failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error<E, P> {
    NotInitialised,
    OutputTooShort { required: usize, available: usize },
    Cipher(E),
    Padding(P),
}

impl<E: fmt::Display, P: fmt::Display> fmt::Display for Error<E, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("CBC-MAC not initialised"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::Cipher(error) => write!(f, "CBC-MAC block cipher failed: {error}"),
            Self::Padding(error) => write!(f, "CBC-MAC padding failed: {error}"),
        }
    }
}

impl<E: core::error::Error, P: core::error::Error> core::error::Error for Error<E, P> {}

/// A CBC-MAC initialization failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitError<E> {
    InvalidIvLength(usize),
    Cipher(E),
}

impl<E: fmt::Display> fmt::Display for InitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIvLength(bytes) => write!(f, "invalid CBC-MAC IV length: {bytes} bytes"),
            Self::Cipher(error) => write!(f, "CBC-MAC block cipher initialization failed: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for InitError<E> {}
