mod cfrg;
mod dsa;
mod ec;
mod elgamal;
mod rsa;

use crate::DefaultAlgoAsn1Context;
use crate::der::decode_all;
use crate::pkcs8::Pkcs8Entry;

pub(crate) type CreateRows = fn(&DefaultAlgoAsn1Context) -> Vec<Box<dyn Pkcs8Entry>>;

// What DefaultPkcsOperatorBuilder starts with. These are always on, as the keys of certificates
// need them
pub(crate) const BUILT_IN: &[CreateRows] =
    &[rsa::rsa, ec::ec, cfrg::cfrg, dsa::dsa, elgamal::elgamal];
