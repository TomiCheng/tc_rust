#[cfg(any(
    feature = "sha1",
    feature = "sha224",
    feature = "sha256",
    feature = "sha384",
    feature = "sha512",
    feature = "sha512-224",
    feature = "sha512-256"
))]
mod sha;

use super::DigestEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn DigestEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the digests whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "sha1")]
    sha::sha1,
    #[cfg(feature = "sha224")]
    sha::sha224,
    #[cfg(feature = "sha256")]
    sha::sha256,
    #[cfg(feature = "sha384")]
    sha::sha384,
    #[cfg(feature = "sha512")]
    sha::sha512,
    #[cfg(feature = "sha512-224")]
    sha::sha512_224,
    #[cfg(feature = "sha512-256")]
    sha::sha512_256,
];
