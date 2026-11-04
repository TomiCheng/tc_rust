use tc_macs::{InitError, MacError};

use crate::ErrorKind;
use crate::cipher::classify::Classify;

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

// tc_iso9797_mac has errors of its own
#[cfg(feature = "iso9797-mac")]
impl Classify for tc_iso9797_mac::InitError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::InvalidParams
    }
}

#[cfg(feature = "iso9797-mac")]
impl<P> Classify for tc_iso9797_mac::Error<P> {
    fn kind(&self) -> ErrorKind {
        use tc_iso9797_mac::Error;
        match self {
            Error::NotInitialised => ErrorKind::NotInitialized,
            Error::OutputTooShort { .. } => ErrorKind::DataLength,
            Error::Cipher(error) => error.kind(),
            _ => ErrorKind::InvalidParams,
        }
    }
}

// tc_dstu_macs has an error of its own for DSTU 7624
#[cfg(feature = "dstu7624-mac")]
impl Classify for tc_dstu_macs::Dstu7624MacError {
    fn kind(&self) -> ErrorKind {
        use tc_dstu_macs::Dstu7624MacError;
        match self {
            Dstu7624MacError::NotInitialised => ErrorKind::NotInitialized,
            Dstu7624MacError::OutputTooShort { .. }
            | Dstu7624MacError::InputNotBlockAligned { .. } => ErrorKind::DataLength,
            _ => ErrorKind::InvalidParams,
        }
    }
}
