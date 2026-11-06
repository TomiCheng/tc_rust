use super::SignerEntry;

pub(crate) type CreateRows = fn(&crate::DefaultAlgoContext) -> Vec<Box<dyn SignerEntry>>;

// What DefaultAlgoBuilder starts with: the rows of the signers whose features are on
pub(crate) const BUILT_IN: &[CreateRows] = &[];
