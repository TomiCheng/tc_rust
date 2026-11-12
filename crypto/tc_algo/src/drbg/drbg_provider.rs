use tc_asn1::Asn1Oid;

use crate::AlgoError;
use crate::drbg::{Drbg, DrbgEntry};

pub trait DrbgProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DrbgEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Drbg>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Drbg>, AlgoError>;
}
