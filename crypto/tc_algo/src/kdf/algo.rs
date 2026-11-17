#[cfg(any(
    feature = "hkdf",
    feature = "kdf1",
    feature = "kdf2",
    feature = "concat-kdf"
))]
mod digest;
#[cfg(feature = "sp800-108")]
mod sp800_108;
#[cfg(any(
    feature = "hkdf",
    feature = "kdf1",
    feature = "kdf2",
    feature = "concat-kdf",
    feature = "sp800-108"
))]
mod typed;

use super::KdfEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the KDFs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(any(
        feature = "hkdf",
        feature = "kdf1",
        feature = "kdf2",
        feature = "concat-kdf"
    ))]
    digest::digest,
    #[cfg(feature = "sp800-108")]
    sp800_108::sp800_108,
];
