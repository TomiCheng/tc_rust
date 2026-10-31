use tc_asn1::Asn1Oid;

use super::table::KEY_PAIR_GENERATORS;
use super::{KeyGenerator, KeyGeneratorEntry, KeyPairGenerator, KeyPairGeneratorEntry};
use crate::{AlgoError, ErrorKind};

pub fn key_generators() -> impl Iterator<Item = &'static KeyGeneratorEntry> {
    todo!() as core::slice::Iter<'static, KeyGeneratorEntry>
}

pub fn get_key_generator(name: &str) -> Result<KeyGenerator, AlgoError> {
    todo!()
}

pub fn get_key_generator_by_oid(oid: &Asn1Oid) -> Result<KeyGenerator, AlgoError> {
    todo!()
}

pub fn key_pair_generators() -> impl Iterator<Item = &'static KeyPairGeneratorEntry> {
    KEY_PAIR_GENERATORS.iter()
}

// Names match without regard to ASCII case; a string that is not a name is parsed as a dotted
// OID, as in Bouncy Castle
pub fn get_key_pair_generator(name: &str) -> Result<KeyPairGenerator, AlgoError> {
    KEY_PAIR_GENERATORS
        .iter()
        .find(|entry| {
            entry
                .names()
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .or_else(|| find_key_pair_generator_by_oid(&name.parse().ok()?))
        .map(KeyPairGeneratorEntry::generator)
        .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
}

pub fn get_key_pair_generator_by_oid(oid: &Asn1Oid) -> Result<KeyPairGenerator, AlgoError> {
    find_key_pair_generator_by_oid(oid)
        .map(KeyPairGeneratorEntry::generator)
        .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
}

fn find_key_pair_generator_by_oid(oid: &Asn1Oid) -> Option<&'static KeyPairGeneratorEntry> {
    KEY_PAIR_GENERATORS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
