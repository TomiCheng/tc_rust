#[cfg(feature = "sha256")]
mod sha256;

use super::DigestEntry;

// What DefaultAlgoBuilder starts with: the rows of the digests whose features are on
pub(crate) const BUILT_IN: &[fn() -> Box<dyn DigestEntry>] = &[
    #[cfg(feature = "sha256")]
    sha256::sha256,
];
