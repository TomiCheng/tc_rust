use tc_asn1::Asn1Oid;

use super::{AnyCipher, CipherEntry};
use crate::AlgoError;

pub fn algorithms() -> impl Iterator<Item = &'static CipherEntry> {
    todo!() as core::slice::Iter<'static, CipherEntry>
}

// The name is the full transformation, such as AES/CBC/PKCS7PADDING, matched without regard to
// ASCII case as in Bouncy Castle
pub fn get_by_name(name: &str) -> Result<AnyCipher, AlgoError> {
    todo!()
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<AnyCipher, AlgoError> {
    todo!()
}
