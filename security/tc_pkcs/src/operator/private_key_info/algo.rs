mod ec;
mod rsa;
mod x25519;

use tc_asn1::{Asn1Error, Decode, DecodingOptions};

use crate::operator::private_key_info::PrivateKeyInfoEntry;
use crate::{DefaultPkcsOperatorContext, PkcsError};

pub(crate) type CreateRows = fn(&DefaultPkcsOperatorContext) -> Vec<Box<dyn PrivateKeyInfoEntry>>;

// What DefaultPkcsOperatorBuilder starts with. These are always on, as the keys of certificates
// need them
pub(crate) const BUILT_IN: &[CreateRows] = &[rsa::rsa, ec::ec, x25519::x25519];

// The structure `bytes` hold, with nothing after it
fn decode_all<T: Decode>(bytes: &[u8]) -> Result<T, PkcsError> {
    let (used, value) = T::decode(bytes, &DecodingOptions::default())?;
    if used != bytes.len() {
        return Err(Asn1Error::TrailingData.into());
    }
    Ok(value)
}
