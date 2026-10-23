use core::convert::Infallible;
use core::error::Error;
use core::fmt;

/// A failure while initializing one of the SP 800-108 functions.
///
/// `E` is the initialization error of the MAC underneath.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfInitError<E = Infallible> {
    /// The counter length is not 8, 16, 24 or 32 bits; the field holds the bits given.
    InvalidCounterLength(usize),
    /// The MAC rejected the key; [`source`](Error::source) returns its error.
    Mac(E),
}

impl<E> fmt::Display for KdfInitError<E> {
    /// Writes a description of this layer only; the MAC's error is reachable through `source`.
    /// Constant time: the fields hold only public lengths.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCounterLength(bits) => {
                write!(
                    f,
                    "KDF counter length must be 8, 16, 24 or 32 bits, not {bits}"
                )
            }
            Self::Mac(_) => f.write_str("KDF MAC rejected its key"),
        }
    }
}

impl<E: Error + 'static> Error for KdfInitError<E> {
    /// Returns the MAC's error for `Mac`, and `None` otherwise. Constant time.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Mac(error) => Some(error),
            _ => None,
        }
    }
}
