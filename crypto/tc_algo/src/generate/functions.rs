use tc_asn1::Asn1Oid;

use super::{KeyGenerator, KeyGeneratorEntry, KeyPairGenerator, KeyPairGeneratorEntry};
use crate::AlgoError;

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
    todo!() as core::slice::Iter<'static, KeyPairGeneratorEntry>
}

pub fn get_key_pair_generator(name: &str) -> Result<KeyPairGenerator, AlgoError> {
    todo!()
}

pub fn get_key_pair_generator_by_oid(oid: &Asn1Oid) -> Result<KeyPairGenerator, AlgoError> {
    todo!()
}
