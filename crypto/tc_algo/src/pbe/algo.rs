#[cfg(feature = "pbe-aes")]
mod aes;

use super::PbeEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn PbeEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the PBE schemes whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "pbe-aes")]
    aes::aes,
];
