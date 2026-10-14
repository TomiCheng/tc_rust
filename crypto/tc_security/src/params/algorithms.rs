use tc_asn1::Asn1Oid;

use super::ParamsEntry;
use crate::SecurityError;
use crate::cipher;

pub fn algorithms() -> impl Iterator<Item = ParamsEntry> {
    cipher::algorithms().map(ParamsEntry::new)
}

pub fn get_by_name(name: &str) -> Result<ParamsEntry, SecurityError> {
    cipher::get_by_name(name).map(ParamsEntry::new)
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<ParamsEntry, SecurityError> {
    cipher::get_by_oid(oid).map(ParamsEntry::new)
}
