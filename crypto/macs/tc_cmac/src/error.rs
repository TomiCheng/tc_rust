//! CMAC construction, initialization, and processing errors.

use core::fmt;

/// A failure while constructing a CMAC instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateError {
    /// CMAC only defines reduction constants for 64- and 128-bit blocks.
    UnsupportedBlockSize(usize),
    /// The requested tag length is zero, exceeds the block size, or is not a
    /// whole number of bytes.
    InvalidMacSize {
        requested_bits: usize,
        maximum_bits: usize,
    },
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedBlockSize(bytes) => {
                write!(
                    f,
                    "CMAC requires an 8- or 16-byte block cipher, got {bytes}"
                )
            }
            Self::InvalidMacSize {
                requested_bits,
                maximum_bits,
            } => write!(
                f,
                "invalid CMAC size: requested {requested_bits} bits, maximum {maximum_bits} bits"
            ),
        }
    }
}

impl core::error::Error for CreateError {}

/// A failure while processing or finalizing CMAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error<E> {
    /// CMAC has not been initialized with a key.
    NotInitialised,
    /// The output buffer is shorter than the configured tag length.
    OutputTooShort { required: usize, available: usize },
    /// The underlying block cipher failed.
    Cipher(E),
    /// ISO/IEC 7816-4 final-block padding failed.
    Padding(tc_pad::PaddingError),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("CMAC not initialised"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::Cipher(error) => write!(f, "CMAC block cipher failed: {error}"),
            Self::Padding(error) => write!(f, "CMAC final-block padding failed: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for Error<E> {}

/// A failure while initializing CMAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitError<I, E> {
    /// Initializing the underlying block cipher failed.
    CipherInit(I),
    /// Encrypting the zero block used to derive CMAC subkeys failed.
    Cipher(E),
}

impl<I: fmt::Display, E: fmt::Display> fmt::Display for InitError<I, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CipherInit(error) => {
                write!(f, "CMAC block cipher initialization failed: {error}")
            }
            Self::Cipher(error) => write!(f, "CMAC subkey derivation failed: {error}"),
        }
    }
}

impl<I: core::error::Error, E: core::error::Error> core::error::Error for InitError<I, E> {}
