#[cfg(any(
    feature = "cbc-mac",
    feature = "cfb-mac",
    feature = "cmac",
    feature = "gmac"
))]
mod block;
#[cfg(feature = "hmac")]
mod hmac;
#[cfg(any(
    feature = "iso9797-alg3-mac",
    feature = "gost28147-mac",
    feature = "vmpc-mac",
    feature = "siphash",
    feature = "kmac",
    feature = "poly1305",
    feature = "skein-mac"
))]
mod keyed;
#[cfg(any(
    feature = "cbc-mac",
    feature = "cfb-mac",
    feature = "cmac",
    feature = "gmac",
    feature = "iso9797-alg3-mac",
    feature = "gost28147-mac",
    feature = "vmpc-mac",
    feature = "siphash",
    feature = "kmac",
    feature = "poly1305",
    feature = "skein-mac"
))]
mod row;

use super::MacEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn MacEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the MACs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "hmac")]
    hmac::hmac,
    #[cfg(any(
        feature = "cbc-mac",
        feature = "cfb-mac",
        feature = "cmac",
        feature = "gmac"
    ))]
    block::block,
    #[cfg(any(
        feature = "iso9797-alg3-mac",
        feature = "gost28147-mac",
        feature = "vmpc-mac",
        feature = "siphash",
        feature = "kmac",
        feature = "poly1305",
        feature = "skein-mac"
    ))]
    keyed::keyed,
];
