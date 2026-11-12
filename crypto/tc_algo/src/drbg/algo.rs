#[cfg(feature = "drbg-hmac-sha256")]
mod hmac_sha256;

use super::DrbgEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn DrbgEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the DRBGs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "drbg-hmac-sha256")]
    hmac_sha256::hmac_sha256,
];
