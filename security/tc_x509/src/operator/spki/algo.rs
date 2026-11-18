mod ec;
mod rsa;
mod x25519;

use crate::DefaultX509OperatorContext;
use crate::operator::spki::SpkiEntry;

pub(crate) type CreateRows = fn(&DefaultX509OperatorContext) -> Vec<Box<dyn SpkiEntry>>;

// What DefaultX509OperatorBuilder starts with. These are always on, as a certificate needs them
pub(crate) const BUILT_IN: &[CreateRows] = &[rsa::rsa, ec::ec, x25519::x25519];
