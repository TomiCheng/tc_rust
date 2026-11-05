use tc_asn1::Asn1Oid;

use crate::digest::{Digest, DigestEntry};
use crate::{AlgoError, ErrorKind};

pub trait DigestProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DigestEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Digest>>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Digest>>;

    fn calculate_by_name(&self, name: &str, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut digest = self
            .get_by_name(name)
            .ok_or(AlgoError::new(ErrorKind::UnknownDigest))?;
        digest.update(input);
        Ok(digest.finalize())
    }

    fn calculate_by_oid(&self, oid: &Asn1Oid, input: &[u8]) -> Result<Vec<u8>, AlgoError> {
        let mut digest = self
            .get_by_oid(oid)
            .ok_or(AlgoError::new(ErrorKind::UnknownDigest))?;
        digest.update(input);
        Ok(digest.finalize())
    }
}
