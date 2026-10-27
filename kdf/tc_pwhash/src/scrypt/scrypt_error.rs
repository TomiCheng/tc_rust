use core::error::Error;
use core::fmt;

use tc_pbe::PbeError;

/// A failure to derive with scrypt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScryptError {
    /// `N` is not a power of two above 1, or is 65536 or more while `r` is 1; the field holds it.
    InvalidCost(u32),
    /// `r` is 0; the field holds it.
    InvalidBlockSize(u32),
    /// `p` is 0 or above `(2^31 - 1) / (1024 * r)`; the field holds it.
    InvalidParallelism(u32),
    /// The output is empty.
    EmptyOutput,
    /// The `128 * r * N` bytes of working memory could not be allocated.
    OutOfMemory,
    /// PBKDF2 failed, as for an output over `(2^32 - 1) * 32` bytes; [`source`](Error::source)
    /// returns its error.
    Pbkdf2(PbeError),
}

impl fmt::Display for ScryptError {
    /// Constant time: no field holds secret data.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCost(n) => write!(f, "scrypt cost N = {n} is not accepted"),
            Self::InvalidBlockSize(r) => write!(f, "scrypt block size r = {r} is not accepted"),
            Self::InvalidParallelism(p) => {
                write!(f, "scrypt parallelization p = {p} is not accepted")
            }
            Self::EmptyOutput => f.write_str("scrypt output is empty"),
            Self::OutOfMemory => f.write_str("scrypt working memory could not be allocated"),
            Self::Pbkdf2(_) => f.write_str("scrypt PBKDF2 failed"),
        }
    }
}

impl Error for ScryptError {
    /// Returns PBKDF2's error for `Pbkdf2`, and `None` otherwise. Constant time.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pbkdf2(error) => Some(error),
            _ => None,
        }
    }
}
