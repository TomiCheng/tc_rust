use core::error::Error;
use core::fmt;

/// A failure while initializing a password-based generator or deriving from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PbeError {
    /// The generator has not been initialized.
    NotInitialised,
    /// The iteration count is one the scheme does not take, such as 0; the field holds it.
    InvalidIterationCount(usize),
    /// The request goes past the most bytes the scheme can derive, such as one digest for
    /// PKCS#5 scheme 1.
    OutputTooLong,
    /// The HMAC under PBKDF2 failed; [`source`](Error::source) returns its error. Available
    /// with the `pbkdf2` feature.
    #[cfg(feature = "pbkdf2")]
    Mac(tc_macs::MacError),
}

impl fmt::Display for PbeError {
    /// Constant time: no field holds secret data.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("PBE generator not initialised"),
            Self::InvalidIterationCount(count) => {
                write!(f, "PBE iteration count {count} is not accepted")
            }
            Self::OutputTooLong => f.write_str("PBE output exceeds the scheme's length limit"),
            #[cfg(feature = "pbkdf2")]
            Self::Mac(_) => f.write_str("PBE HMAC failed"),
        }
    }
}

impl Error for PbeError {
    /// Returns the HMAC's error for `Mac`, and `None` otherwise. Constant time.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            #[cfg(feature = "pbkdf2")]
            Self::Mac(error) => Some(error),
            _ => None,
        }
    }
}
