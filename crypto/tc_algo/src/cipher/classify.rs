use core::convert::Infallible;

use tc_aead_cipher::{AeadError, AeadInitError};
use tc_block_cipher::{BlockError, InitError};
use tc_block_modes::{BlockModeError, BlockModeInitError};
use tc_buffered_cipher::BufferedError;

use crate::{AlgoError, ErrorKind};

// Sorts the errors of the layers underneath into an ErrorKind; the error itself travels as the
// source. Bad padding and a failed tag both come out as InvalidCiphertext: telling them apart is
// what a padding oracle needs
pub(super) trait Classify {
    fn kind(&self) -> ErrorKind;
}

impl Classify for AlgoError {
    fn kind(&self) -> ErrorKind {
        AlgoError::kind(self)
    }
}

impl Classify for Infallible {
    fn kind(&self) -> ErrorKind {
        match *self {}
    }
}

impl Classify for BlockError {
    fn kind(&self) -> ErrorKind {
        match self {
            BlockError::NotInitialised => ErrorKind::NotInitialized,
            _ => ErrorKind::DataLength,
        }
    }
}

impl Classify for InitError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::InvalidParams
    }
}

impl<E: Classify> Classify for BlockModeError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            BlockModeError::NotInitialised => ErrorKind::NotInitialized,
            BlockModeError::Cipher(error) => error.kind(),
            _ => ErrorKind::DataLength,
        }
    }
}

impl<E: Classify> Classify for BlockModeInitError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            BlockModeInitError::Cipher(error) => error.kind(),
            _ => ErrorKind::InvalidParams,
        }
    }
}

impl<E: Classify> Classify for BufferedError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            BufferedError::NotInitialized => ErrorKind::NotInitialized,
            BufferedError::CorruptPadding => ErrorKind::InvalidCiphertext,
            BufferedError::Cipher(error) => error.kind(),
            // The lengths that do not fit: a partial last block, too long an input or too short
            // an output
            _ => ErrorKind::DataLength,
        }
    }
}

impl<E: Classify> Classify for AeadError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            // A finished GCM encryption takes a new init, so that no nonce is used twice
            AeadError::NotInitialized | AeadError::AlreadyFinalized => ErrorKind::NotInitialized,
            // Too short to hold the tag is told apart no more than a wrong tag
            AeadError::AuthenticationFailed | AeadError::CiphertextTooShort { .. } => {
                ErrorKind::InvalidCiphertext
            }
            AeadError::Cipher(error) => error.kind(),
            _ => ErrorKind::DataLength,
        }
    }
}

impl<E: Classify> Classify for AeadInitError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            AeadInitError::Cipher(error) => error.kind(),
            _ => ErrorKind::InvalidParams,
        }
    }
}

// The AlgoError of an error from underneath: its kind, with the error itself as the source
pub(super) fn to_algo_error<E>(error: E) -> AlgoError
where
    E: Classify + core::error::Error + Send + Sync + 'static,
{
    AlgoError::with_source(error.kind(), error)
}
