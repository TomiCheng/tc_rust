mod rsa;

use crate::DefaultX509OperatorContext;
use crate::operator::signer::SignerEntry;

pub(crate) type CreateRows = fn(&DefaultX509OperatorContext) -> Vec<Box<dyn SignerEntry>>;

// What DefaultX509OperatorBuilder starts with. These are always on, as a certificate needs them
pub(crate) const BUILT_IN: &[CreateRows] = &[rsa::rsa];
