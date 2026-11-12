use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::generate::{KeyGenerator, KeyGeneratorEntry, KeyGeneratorProvider};
use crate::{AlgoError, ErrorKind};

impl KeyGeneratorProvider for DefaultProvider<dyn KeyGeneratorEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyGeneratorEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn KeyGeneratorEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn KeyGenerator>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn KeyGenerator>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
    }
}
