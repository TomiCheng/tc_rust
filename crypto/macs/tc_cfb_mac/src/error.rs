use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateError {
    InvalidBlockSize(usize),
    InvalidFeedbackSize(usize),
    InvalidMacSize {
        requested_bits: usize,
        maximum_bits: usize,
    },
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize(bytes) => write!(f, "invalid CFB-MAC block size: {bytes} bytes"),
            Self::InvalidFeedbackSize(bits) => {
                write!(f, "invalid CFB-MAC feedback size: {bits} bits")
            }
            Self::InvalidMacSize {
                requested_bits,
                maximum_bits,
            } => write!(
                f,
                "invalid CFB-MAC size: requested {requested_bits} bits, maximum {maximum_bits} bits"
            ),
        }
    }
}

impl core::error::Error for CreateError {}

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
            Self::NotInitialised => f.write_str("CFB-MAC not initialised"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::Cipher(error) => write!(f, "CFB-MAC block cipher failed: {error}"),
            Self::Padding(error) => write!(f, "CFB-MAC padding failed: {error}"),
        }
    }
}

impl<E: core::error::Error, P: core::error::Error> core::error::Error for Error<E, P> {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitError<E> {
    Cipher(E),
}

impl<E: fmt::Display> fmt::Display for InitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cipher(error) => write!(f, "CFB-MAC block cipher initialization failed: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for InitError<E> {}
