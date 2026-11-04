use core::convert::Infallible;
use core::error::Error;

use tc_macs::{InitError, MacError};

use crate::{AlgoError, ErrorKind};

// Sorts the errors of the layers underneath into an ErrorKind; the error itself travels as the
// source
pub(super) trait Classify {
    fn kind(&self) -> ErrorKind;
}

impl Classify for Infallible {
    fn kind(&self) -> ErrorKind {
        match *self {}
    }
}

impl<E: Classify> Classify for MacError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            MacError::NotInitialised => ErrorKind::NotInitialized,
            MacError::OutputTooShort { .. } | MacError::InputTooLong => ErrorKind::DataLength,
            MacError::Cipher(error) => error.kind(),
            _ => ErrorKind::InvalidParams,
        }
    }
}

impl<E: Classify> Classify for InitError<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            InitError::Cipher(error) => error.kind(),
            _ => ErrorKind::InvalidParams,
        }
    }
}

pub(super) fn to_algo_error<E>(error: E) -> AlgoError
where
    E: Classify + Error + Send + Sync + 'static,
{
    AlgoError::with_source(error.kind(), error)
}
