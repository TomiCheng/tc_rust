use tc_asn1::Asn1Oid;

use crate::AlgoError;
use crate::agreement::{Agreement, AgreementEntry};

pub trait AgreementProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn AgreementEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Agreement>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Agreement>, AlgoError>;
}
