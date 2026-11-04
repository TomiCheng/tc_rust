use tc_asn1::Asn1Oid;

use super::table::MACS;
use super::{AnyMac, MacEntry};
use crate::{AlgoError, ErrorKind};

pub fn algorithms() -> impl Iterator<Item = &'static MacEntry> {
    MACS.iter()
}

// Names match without regard to ASCII case, aliases included; a string that is not a name is parsed
// as a dotted OID, as in Bouncy Castle
pub fn get_by_name(name: &str) -> Result<AnyMac, AlgoError> {
    MACS.iter()
        .find(|entry| {
            entry
                .names()
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .or_else(|| find_by_oid(&name.parse().ok()?))
        .map(MacEntry::mac)
        .ok_or(AlgoError::new(ErrorKind::UnknownMac))
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<AnyMac, AlgoError> {
    find_by_oid(oid)
        .map(MacEntry::mac)
        .ok_or(AlgoError::new(ErrorKind::UnknownMac))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static MacEntry> {
    MACS.iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
