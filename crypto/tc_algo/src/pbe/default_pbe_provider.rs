use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::pbe::{Pbe, PbeEntry, PbeProvider};
use crate::{AlgoError, ErrorKind};

impl PbeProvider for DefaultProvider<dyn PbeEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn PbeEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn PbeEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Pbe>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownPbe))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Pbe>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownPbe))
    }
}
