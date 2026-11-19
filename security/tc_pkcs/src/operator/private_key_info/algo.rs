mod ec;
mod rsa;
mod x25519;

use crate::DefaultPkcsOperatorContext;
use crate::der::decode_all;
use crate::operator::private_key_info::PrivateKeyInfoEntry;

pub(crate) type CreateRows = fn(&DefaultPkcsOperatorContext) -> Vec<Box<dyn PrivateKeyInfoEntry>>;

// What DefaultPkcsOperatorBuilder starts with. These are always on, as the keys of certificates
// need them
pub(crate) const BUILT_IN: &[CreateRows] = &[rsa::rsa, ec::ec, x25519::x25519];
