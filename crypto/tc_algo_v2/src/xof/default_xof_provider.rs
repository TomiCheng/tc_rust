use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::xof::{Xof, XofEntry, XofProvider};
use crate::{AlgoError, ErrorKind};

impl XofProvider for DefaultProvider<dyn XofEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn XofEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn XofEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Xof>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownXof))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Xof>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownXof))
    }
}
