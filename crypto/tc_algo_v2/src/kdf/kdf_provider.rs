use tc_asn1::Asn1Oid;

use crate::AlgoError;
use crate::kdf::{Kdf, KdfEntry};

pub trait KdfProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KdfEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Kdf>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Kdf>, AlgoError>;
}
