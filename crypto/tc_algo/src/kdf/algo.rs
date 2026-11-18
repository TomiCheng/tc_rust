#[cfg(any(feature = "kdf", feature = "pbe"))]
mod digest;
#[cfg(feature = "pbe")]
mod pbkdf2;
#[cfg(feature = "kdf")]
mod sp800_108;
#[cfg(any(feature = "kdf", feature = "pbe"))]
mod typed;

use super::KdfEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the KDFs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(any(feature = "kdf", feature = "pbe"))]
    digest::digest,
    #[cfg(feature = "kdf")]
    sp800_108::sp800_108,
];
