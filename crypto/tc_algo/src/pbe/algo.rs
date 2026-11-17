#[cfg(feature = "pbe")]
mod schemes;

use super::PbeEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn PbeEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the PBE schemes whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "pbe")]
    schemes::schemes,
];
