use crate::{AlgoError, ErrorKind};

// Whether an algorithm needs an operation field: init refuses a required one that is missing and a
// forbidden one that is there, so nothing is filled in silently or dropped silently
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Need {
    Forbidden,
    Optional,
    Required,
}

impl Need {
    pub(crate) fn check(self, present: bool) -> Result<(), AlgoError> {
        match (self, present) {
            (Need::Required, false) | (Need::Forbidden, true) => {
                Err(AlgoError::new(ErrorKind::InvalidParams))
            }
            _ => Ok(()),
        }
    }
}
