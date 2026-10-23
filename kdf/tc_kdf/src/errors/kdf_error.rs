use core::convert::Infallible;
use core::error::Error;
use core::fmt;

/// A failure while deriving bytes.
///
/// `E` is the error of the MAC underneath, for HKDF and the SP 800-108 functions; a function
/// over a digest keeps the default `Infallible`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfError<E = Infallible> {
    /// The function has not been initialized.
    NotInitialised,
    /// The request goes past the most bytes the function can derive, such as
    /// `(2^32 - 1) * digest size` for KDF2 or `255 * hash size` in all for HKDF.
    OutputTooLong,
    /// The MAC underneath failed; [`source`](Error::source) returns its error.
    Mac(E),
}

impl<E> fmt::Display for KdfError<E> {
    /// Writes a description of this layer only; the MAC's error is reachable through `source`.
    /// Constant time: no field holds secret data.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("KDF not initialised"),
            Self::OutputTooLong => f.write_str("KDF output exceeds the function's length limit"),
            Self::Mac(_) => f.write_str("KDF MAC failed"),
        }
    }
}

impl<E: Error + 'static> Error for KdfError<E> {
    /// Returns the MAC's error for `Mac`, and `None` otherwise. Constant time.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Mac(error) => Some(error),
            _ => None,
        }
    }
}
