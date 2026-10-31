use tc_asn1::Asn1Oid;

use super::{Algorithm, AnyDigest, DigestEntry};
use crate::AlgoError;

pub fn algorithms() -> impl Iterator<Item = &'static DigestEntry> {
    todo!() as core::slice::Iter<'static, DigestEntry>
}

pub fn get(algorithm: Algorithm) -> AnyDigest {
    todo!()
}

pub fn get_by_name(name: &str) -> Result<AnyDigest, AlgoError> {
    todo!()
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<AnyDigest, AlgoError> {
    todo!()
}
