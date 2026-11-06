use tc_asn1::Asn1Oid;

use crate::AlgoError;
use crate::pbe::{Pbe, PbeEntry};

pub trait PbeProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn PbeEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Pbe>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Pbe>, AlgoError>;
}
