#[cfg(feature = "hkdf")]
mod hkdf;

use super::KdfEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn KdfEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the KDFs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "hkdf-sha256")]
    hkdf::hkdf_sha256,
    #[cfg(feature = "hkdf-sha384")]
    hkdf::hkdf_sha384,
    #[cfg(feature = "hkdf-sha512")]
    hkdf::hkdf_sha512,
];
