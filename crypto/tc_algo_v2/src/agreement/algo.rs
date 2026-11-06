#[cfg(feature = "dh")]
mod dh;

use super::AgreementEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn AgreementEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the agreements whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "dh")]
    dh::dh,
];
