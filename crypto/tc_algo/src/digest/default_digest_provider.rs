use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::digest::{Digest, DigestEntry, DigestProvider};
use crate::{AlgoError, ErrorKind};

impl DigestProvider for DefaultProvider<dyn DigestEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DigestEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn DigestEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Digest>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownDigest))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Digest>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownDigest))
    }
}
