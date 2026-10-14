use tc_asn1::Asn1Oid;

use super::ParamsEntry;
use crate::SecurityError;

pub fn algorithms() -> impl Iterator<Item = ParamsEntry> {
    todo!() as core::iter::Empty<ParamsEntry>
}

pub fn get_by_name(name: &str) -> Result<ParamsEntry, SecurityError> {
    todo!("{name}")
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<ParamsEntry, SecurityError> {
    todo!("{oid}")
}
