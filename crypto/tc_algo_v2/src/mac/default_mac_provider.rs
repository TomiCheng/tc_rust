use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::{AlgoError, ErrorKind, Mac, MacEntry, MacProvider};

impl MacProvider for DefaultProvider<dyn MacEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn MacEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn MacEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Mac>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownMac))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Mac>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownMac))
    }
}
