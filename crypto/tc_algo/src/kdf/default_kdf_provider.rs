use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::kdf::{Kdf, KdfEntry, KdfProvider};
use crate::{AlgoError, ErrorKind};

impl KdfProvider for DefaultProvider<dyn KdfEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KdfEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn KdfEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Kdf>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownKdf))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Kdf>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownKdf))
    }
}
