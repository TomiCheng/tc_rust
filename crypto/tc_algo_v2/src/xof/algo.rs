#[cfg(feature = "shake256")]
mod shake256;

use super::XofEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn XofEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the XOFs whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "shake256")]
    shake256::shake256,
];
