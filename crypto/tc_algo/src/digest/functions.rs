use tc_asn1::Asn1Oid;

use super::table::DIGESTS;
use super::{Algorithm, AnyDigest, DigestEntry};
use crate::{AlgoError, ErrorKind};

pub fn algorithms() -> impl Iterator<Item = &'static DigestEntry> {
    DIGESTS.iter()
}

pub fn get(algorithm: Algorithm) -> AnyDigest {
    algorithm.entry().create()
}

// Names match without regard to ASCII case; a string that is not a name is parsed as a dotted
// OID, as in Bouncy Castle
pub fn get_by_name(name: &str) -> Result<AnyDigest, AlgoError> {
    find(name)
        .map(DigestEntry::create)
        .ok_or(AlgoError::new(ErrorKind::UnknownDigest))
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<AnyDigest, AlgoError> {
    find_by_oid(oid)
        .map(DigestEntry::create)
        .ok_or(AlgoError::new(ErrorKind::UnknownDigest))
}

fn find(name: &str) -> Option<&'static DigestEntry> {
    DIGESTS
        .iter()
        .find(|entry| {
            entry
                .names()
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .or_else(|| find_by_oid(&name.parse().ok()?))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static DigestEntry> {
    DIGESTS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
