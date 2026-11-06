use tc_asn1::Asn1Oid;

use crate::AlgoError;
use crate::digest::{Digest, DigestEntry};

pub trait DigestProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DigestEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Digest>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Digest>, AlgoError>;

    fn calculate_by_name(&self, name: &str, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut digest = self.get_by_name(name)?;
        digest.update(input);
        Ok(digest.finalize())
    }

    fn calculate_by_oid(&self, oid: &Asn1Oid, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut digest = self.get_by_oid(oid)?;
        digest.update(input);
        Ok(digest.finalize())
    }
}
