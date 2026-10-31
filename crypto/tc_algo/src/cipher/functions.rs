use tc_asn1::Asn1Oid;

use super::table::{self, CIPHERS};
use super::{AnyCipher, CipherEntry};
use crate::{AlgoError, ErrorKind};

pub fn algorithms() -> impl Iterator<Item = &'static CipherEntry> {
    CIPHERS.iter()
}

// The name is the full transformation, such as AES/CBC/PKCS7PADDING, matched as Bouncy Castle
// does: without regard to ASCII case, with '-' and '_' the same, ECB for a missing mode and the
// mode's default for a missing padding
pub fn get_by_name(name: &str) -> Result<AnyCipher, AlgoError> {
    table::find(name)
        .map(CipherEntry::cipher)
        .ok_or(AlgoError::new(ErrorKind::UnknownCipher))
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<AnyCipher, AlgoError> {
    CIPHERS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
        .map(CipherEntry::cipher)
        .ok_or(AlgoError::new(ErrorKind::UnknownCipher))
}
