mod dsa;
mod ec;
mod eddsa;
mod rsa;
mod x25519;

use crate::DefaultAlgoAsn1Context;
use crate::spki::SpkiEntry;

pub(crate) type CreateRows = fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn SpkiEntry>>;

// What DefaultAlgoAsn1Builder starts with. These are always on, as a certificate needs them
pub(crate) const BUILT_IN: &[CreateRows] =
    &[rsa::rsa, ec::ec, x25519::x25519, eddsa::eddsa, dsa::dsa];
