#[cfg(feature = "key-wrap")]
mod block;
#[cfg(feature = "key-wrap")]
mod row;

use super::WrapperEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn WrapperEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the wrappers whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(feature = "key-wrap")]
    block::block,
];
