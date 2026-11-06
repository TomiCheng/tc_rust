use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::{
    AlgoError, ErrorKind, KeyPairGenerator, KeyPairGeneratorEntry, KeyPairGeneratorProvider,
};

impl KeyPairGeneratorProvider for DefaultProvider<dyn KeyPairGeneratorEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyPairGeneratorEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn KeyPairGeneratorEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn KeyPairGenerator>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn KeyPairGenerator>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
    }
}
