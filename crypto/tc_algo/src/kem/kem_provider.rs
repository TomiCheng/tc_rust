use tc_asn1::Asn1Oid;

use crate::AlgoError;
use crate::kem::{Kem, KemEntry};

pub trait KemProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KemEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Kem>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Kem>, AlgoError>;
}
