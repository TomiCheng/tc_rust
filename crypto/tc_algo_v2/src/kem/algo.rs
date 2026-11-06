#[cfg(feature = "ml-kem")]
mod ml_kem;

use super::KemEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn KemEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the KEMs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "ml-kem")]
    ml_kem::ml_kem,
];
