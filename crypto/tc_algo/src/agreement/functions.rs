use tc_asn1::Asn1Oid;

use super::{AgreementEntry, AnyAgreement};
use crate::AlgoError;

// Filled in as the agreements are wired in
static AGREEMENTS: &[AgreementEntry] = &[];

pub fn algorithms() -> impl Iterator<Item = &'static AgreementEntry> {
    AGREEMENTS.iter()
}

// Matched as Bouncy Castle does: without regard to ASCII case, with '-' and '_' the same, and
// with its aliases, such as DIFFIEHELLMAN for DH
pub fn get_by_name(name: &str) -> Result<AnyAgreement, AlgoError> {
    todo!()
}

pub fn get_by_oid(oid: &Asn1Oid) -> Result<AnyAgreement, AlgoError> {
    todo!()
}
