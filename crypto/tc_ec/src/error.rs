use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcError {}

impl fmt::Display for EcError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}

impl core::error::Error for EcError {}
