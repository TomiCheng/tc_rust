mod pbe;
mod pbes2;
mod rc2_cbc;

use tc_asn1::Asn1Integer;

use crate::operator::encrypted_private_key_info::EncryptedPrivateKeyInfoEntry;
use crate::{DefaultPkcsOperatorContext, PkcsError};

pub(crate) type CreateRows =
    fn(&DefaultPkcsOperatorContext) -> Vec<Box<dyn EncryptedPrivateKeyInfoEntry>>;

// What DefaultPkcsOperatorBuilder starts with: the PBE schemes of tc_algo that have an OID, and
// PBES2
pub(crate) const BUILT_IN: &[CreateRows] = &[pbe::pbe, pbes2::pbes2];

fn to_usize(value: &Asn1Integer) -> Result<usize, PkcsError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(PkcsError::InvalidEncryptionParams)
}
