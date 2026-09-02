//! Errors for authenticated block-cipher constructions.

use core::fmt;

use crate::AeadError;

/// A processing or finalization error from an AEAD block-cipher construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadBlockError<E> {
    /// A failure in the AEAD construction itself.
    Aead(AeadError),
    /// A failure reported by the underlying block cipher.
    Cipher(E),
}

impl<E: fmt::Display> fmt::Display for AeadBlockError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead(error) => error.fmt(f),
            Self::Cipher(error) => write!(f, "underlying block cipher failed: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for AeadBlockError<E> {}

/// An initialization error from an AEAD block-cipher construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadBlockInitError<E> {
    /// The underlying block cipher does not use 16-byte blocks as required.
    InvalidBlockSize(usize),
    /// The nonce length is outside the range supported by the construction.
    InvalidNonceLength(usize),
    /// The requested authentication-tag size is unsupported.
    InvalidMacSize(usize),
    /// The same key and nonce would be reused for encryption.
    NonceReuse,
    /// Initialization of the underlying block cipher failed.
    Cipher(E),
}

impl<E: fmt::Display> fmt::Display for AeadBlockInitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize(bytes) => {
                write!(f, "invalid AEAD block cipher size: {bytes} bytes")
            }
            Self::InvalidNonceLength(bytes) => {
                write!(f, "invalid AEAD nonce length: {bytes} bytes")
            }
            Self::InvalidMacSize(bytes) => {
                write!(f, "invalid AEAD authentication-tag size: {bytes} bytes")
            }
            Self::NonceReuse => f.write_str("key and nonce cannot be reused for AEAD encryption"),
            Self::Cipher(error) => {
                write!(f, "underlying block cipher initialization failed: {error}")
            }
        }
    }
}

impl<E: core::error::Error> core::error::Error for AeadBlockInitError<E> {}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::{AeadBlockError, AeadBlockInitError};
    use crate::{AeadError, BlockError, InitError};

    #[test]
    fn reports_construction_and_cipher_errors() {
        assert_eq!(
            format!(
                "{}",
                AeadBlockError::<BlockError>::Aead(AeadError::AuthenticationFailed)
            ),
            "authentication tag verification failed"
        );
        assert_eq!(
            format!("{}", AeadBlockError::Cipher(BlockError::NotInitialised)),
            "underlying block cipher failed: block cipher not initialised"
        );
        assert_eq!(
            format!("{}", AeadBlockInitError::<InitError>::InvalidMacSize(5)),
            "invalid AEAD authentication-tag size: 5 bytes"
        );
        assert_eq!(
            format!(
                "{}",
                AeadBlockInitError::Cipher(InitError::InvalidKeyLength(7))
            ),
            "underlying block cipher initialization failed: invalid cipher key length: 7 bytes"
        );
    }
}
