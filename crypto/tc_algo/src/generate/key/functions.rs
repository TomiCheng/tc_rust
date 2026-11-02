use tc_asn1::Asn1Oid;

use super::table::KEY_GENERATORS;
use super::{KeyGenerator, KeyGeneratorEntry};
use crate::{AlgoError, ErrorKind};

pub fn algorithms() -> impl Iterator<Item = &'static KeyGeneratorEntry> {
    KEY_GENERATORS.iter()
}

// Names match without regard to ASCII case; a string that is not a name is parsed as a dotted
// OID, as in Bouncy Castle
pub fn get_by_name(name: &str) -> Result<KeyGenerator, AlgoError> {
    KEY_GENERATORS
        .iter()
        .find(|entry| matches_name(entry.names(), name))
        .or_else(|| find_by_oid(&name.parse().ok()?))
        .map(KeyGeneratorEntry::generator)
        .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<KeyGenerator, AlgoError> {
    find_by_oid(oid)
        .map(KeyGeneratorEntry::generator)
        .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
}

fn matches_name(names: &[&str], name: &str) -> bool {
    names.iter().any(|known| known.eq_ignore_ascii_case(name))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static KeyGeneratorEntry> {
    KEY_GENERATORS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
