use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::io;

use tc_asn1::Asn1Error;
use tc_security::{AnyError, SecurityError};

#[derive(Debug)]
pub enum OperatorError {
    Asn1(Asn1Error),
    Security(SecurityError),
    Signer(AnyError),
    Io(io::Error),
}

impl fmt::Display for OperatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(error) => error.fmt(f),
            Self::Security(error) => error.fmt(f),
            Self::Signer(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl Error for OperatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Asn1(error) => Some(error),
            Self::Security(error) => Some(error),
            Self::Signer(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<Asn1Error> for OperatorError {
    fn from(error: Asn1Error) -> Self {
        Self::Asn1(error)
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

impl From<Infallible> for OperatorError {
    fn from(error: Infallible) -> Self {
        match error {}
    }
}

impl From<io::Error> for OperatorError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
