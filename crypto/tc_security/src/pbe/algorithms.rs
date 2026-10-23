use tc_asn1::Asn1Oid;

use super::PbeEntry;
use super::table::SCHEMES;
use crate::SecurityError;

pub fn algorithms() -> impl Iterator<Item = &'static PbeEntry> {
    SCHEMES.iter()
}

/// 名稱比對不分大小寫；不是名稱時改當點分 OID 解析，同 BC。
pub fn get_by_name(name: &str) -> Result<&'static PbeEntry, SecurityError> {
    SCHEMES
        .iter()
        .find(|entry| {
            entry
                .names()
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })
        .or_else(|| find_by_oid(&name.parse().ok()?))
        .ok_or(SecurityError::UnknownPbe)
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<&'static PbeEntry, SecurityError> {
    find_by_oid(oid).ok_or(SecurityError::UnknownPbe)
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static PbeEntry> {
    SCHEMES
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
