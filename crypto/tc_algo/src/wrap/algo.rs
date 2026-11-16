#[cfg(any(
    feature = "rfc3394-wrap",
    feature = "rfc5649-wrap",
    feature = "rfc3211-wrap"
))]
mod block;
#[cfg(any(
    feature = "rfc3394-wrap",
    feature = "rfc5649-wrap",
    feature = "rfc3211-wrap"
))]
mod row;

use super::WrapperEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn WrapperEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the wrappers whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[
    #[cfg(any(
        feature = "rfc3394-wrap",
        feature = "rfc5649-wrap",
        feature = "rfc3211-wrap"
    ))]
    block::block,
];
