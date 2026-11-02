use tc_asn1::Asn1Oid;

use super::table::AGREEMENTS;
use super::{AgreementEntry, AnyAgreement};
use crate::{AlgoError, ErrorKind};

pub fn algorithms() -> impl Iterator<Item = &'static AgreementEntry> {
    AGREEMENTS.iter()
}

// Names match without regard to ASCII case, aliases such as DIFFIEHELLMAN included; a string that
// is not a name is parsed as a dotted OID, as in Bouncy Castle
pub fn get_by_name(name: &str) -> Result<AnyAgreement, AlgoError> {
    AGREEMENTS
        .iter()
        .find(|entry| matches_name(entry.names(), name))
        .or_else(|| find_by_oid(&name.parse().ok()?))
        .map(AgreementEntry::agreement)
        .ok_or(AlgoError::new(ErrorKind::UnknownAgreement))
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<AnyAgreement, AlgoError> {
    find_by_oid(oid)
        .map(AgreementEntry::agreement)
        .ok_or(AlgoError::new(ErrorKind::UnknownAgreement))
}

fn matches_name(names: &[&str], name: &str) -> bool {
    names.iter().any(|known| known.eq_ignore_ascii_case(name))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static AgreementEntry> {
    AGREEMENTS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
