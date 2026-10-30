use std::error::Error;
use std::fmt;
use std::io;

use tc_security::{AnyError, SecurityError};

#[derive(Debug)]
pub enum OperatorError {
    Security(SecurityError),
    Signer(AnyError),
    Io(io::Error),
}

impl fmt::Display for OperatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Security(error) => error.fmt(f),
            Self::Signer(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl Error for OperatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Security(error) => Some(error),
            Self::Signer(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<SecurityError> for OperatorError {
    fn from(error: SecurityError) -> Self {
        Self::Security(error)
    }
}

impl From<AnyError> for OperatorError {
    fn from(error: AnyError) -> Self {
        Self::Signer(error)
    }
}

impl From<io::Error> for OperatorError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
