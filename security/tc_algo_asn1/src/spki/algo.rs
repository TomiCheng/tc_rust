mod dsa;
mod ec;
mod eddsa;
mod rsa;
mod xdh;

use crate::DefaultAlgoAsn1Context;
use crate::spki::SpkiEntry;

pub(crate) type CreateRows = fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn SpkiEntry>>;

// What DefaultAlgoAsn1Builder starts with. These are always on, as a certificate needs them
pub(crate) const BUILT_IN: &[CreateRows] = &[rsa::rsa, ec::ec, xdh::xdh, eddsa::eddsa, dsa::dsa];
