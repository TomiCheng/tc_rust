#[cfg(feature = "hmac-sha256")]
mod hmac_sha256;

use super::MacEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn MacEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the MACs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "hmac-sha256")]
    hmac_sha256::hmac_sha256,
];
