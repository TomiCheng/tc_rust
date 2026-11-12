use tc_key_wrap::{KeyWrapError, KeyWrapInitError};

use crate::ErrorKind;
use crate::cipher::classify::Classify;

// A wrapped key that is the wrong length and one that fails its check both come out as
// InvalidCiphertext, as a bad padding and a failed tag do in the cipher factory
impl<E: Classify> Classify for KeyWrapError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            KeyWrapError::NotInitialized => ErrorKind::NotInitialized,
            KeyWrapError::InvalidUnwrapLength | KeyWrapError::IntegrityCheckFailed => {
                ErrorKind::InvalidCiphertext
            }
            KeyWrapError::InvalidWrapLength | KeyWrapError::OutputTooShort { .. } => {
                ErrorKind::DataLength
            }
            KeyWrapError::Cipher(error) => error.kind(),
            _ => ErrorKind::InvalidParams,
        }
    }
}

impl<E: Classify> Classify for KeyWrapInitError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            KeyWrapInitError::Cipher(error) => error.kind(),
            _ => ErrorKind::InvalidParams,
        }
    }
}
