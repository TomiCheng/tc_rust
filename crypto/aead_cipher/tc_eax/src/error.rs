//! Initialization errors specific to EAX's CMAC setup.

use core::fmt;

/// A failure while initializing an EAX instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EaxInitError<I, E> {
    /// CMAC does not define a reduction constant for this block size.
    InvalidBlockSize(usize),
    /// The requested authentication-tag size is unsupported.
    InvalidMacSize(usize),
    /// The same key and nonce would be reused for encryption.
    NonceReuse,
    /// Initializing the underlying block cipher failed.
    CipherInit(I),
    /// Preparing the CMAC subkeys or nonce authentication failed.
    Cipher(E),
}

impl<I: fmt::Display, E: fmt::Display> fmt::Display for EaxInitError<I, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize(bytes) => {
                write!(f, "EAX requires an 8- or 16-byte block cipher, got {bytes}")
            }
            Self::InvalidMacSize(bytes) => {
                write!(f, "invalid EAX authentication-tag size: {bytes} bytes")
            }
            Self::NonceReuse => f.write_str("key and nonce cannot be reused for EAX encryption"),
            Self::CipherInit(error) => {
                write!(f, "EAX block cipher initialization failed: {error}")
            }
            Self::Cipher(error) => write!(f, "EAX CMAC setup failed: {error}"),
        }
    }
}

impl<I: core::error::Error, E: core::error::Error> core::error::Error for EaxInitError<I, E> {}
