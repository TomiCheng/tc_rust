use core::fmt;

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgoError {
    UnknownDigest,
}

impl fmt::Display for AlgoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlgoError::UnknownDigest => f.write_str("unknown digest algorithm"),
        }
    }
}

impl core::error::Error for AlgoError {}
