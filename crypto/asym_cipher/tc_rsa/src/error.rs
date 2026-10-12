//! The errors of RSA.

/// What can go wrong in RSA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaError {
    /// The operation ran before it was initialized.
    NotInitialized,
}

/// The message of each error. Constant time.
impl core::fmt::Display for RsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "RSA operation not initialized",
        })
    }
}

impl core::error::Error for RsaError {}
