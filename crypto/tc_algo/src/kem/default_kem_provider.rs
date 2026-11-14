use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::kem::{Decapsulator, Encapsulator, KemEntry, KemProvider};
use crate::{AlgoError, ErrorKind};

impl KemProvider for DefaultProvider<dyn KemEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KemEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn KemEntry))
    }

    fn get_encapsulator_by_name(&self, name: &str) -> Result<Box<dyn Encapsulator>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create_encapsulator())
            .ok_or(AlgoError::new(ErrorKind::UnknownKem))
    }

    fn get_encapsulator_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Encapsulator>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create_encapsulator())
            .ok_or(AlgoError::new(ErrorKind::UnknownKem))
    }

    fn get_decapsulator_by_name(&self, name: &str) -> Result<Box<dyn Decapsulator>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create_decapsulator())
            .ok_or(AlgoError::new(ErrorKind::UnknownKem))
    }

    fn get_decapsulator_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Decapsulator>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create_decapsulator())
            .ok_or(AlgoError::new(ErrorKind::UnknownKem))
    }
}
