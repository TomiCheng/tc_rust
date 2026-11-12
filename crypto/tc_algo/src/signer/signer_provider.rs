use tc_asn1::Asn1Oid;

use crate::AlgoError;
use crate::signer::{Signer, SignerEntry};

pub trait SignerProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn SignerEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Signer>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Signer>, AlgoError>;
}
