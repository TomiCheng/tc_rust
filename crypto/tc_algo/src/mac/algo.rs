#[cfg(feature = "macs")]
mod block;
#[cfg(feature = "macs")]
mod hmac;
#[cfg(any(
    feature = "iso9797-mac",
    feature = "gost28147-mac",
    feature = "macs",
    feature = "kmac",
    feature = "poly1305",
    feature = "skein-mac"
))]
mod keyed;
#[cfg(any(
    feature = "macs",
    feature = "iso9797-mac",
    feature = "gost28147-mac",
    feature = "kmac",
    feature = "poly1305",
    feature = "skein-mac"
))]
mod row;

use super::MacEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn MacEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the MACs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "macs")]
    hmac::hmac,
    #[cfg(feature = "macs")]
    block::block,
    #[cfg(any(
        feature = "iso9797-mac",
        feature = "gost28147-mac",
        feature = "macs",
        feature = "kmac",
        feature = "poly1305",
        feature = "skein-mac"
    ))]
    keyed::keyed,
];
