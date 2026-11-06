use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::{AlgoError, ErrorKind, Wrapper, WrapperEntry, WrapperProvider};

impl WrapperProvider for DefaultProvider<dyn WrapperEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn WrapperEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn WrapperEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Wrapper>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownWrapper))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Wrapper>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownWrapper))
    }
}
