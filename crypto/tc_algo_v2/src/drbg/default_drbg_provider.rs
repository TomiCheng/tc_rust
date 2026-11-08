use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::drbg::{Drbg, DrbgEntry, DrbgProvider};
use crate::{AlgoError, ErrorKind};

impl DrbgProvider for DefaultProvider<dyn DrbgEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DrbgEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn DrbgEntry))
    }

    fn get_by_name(&self, name: &str) -> Result<Box<dyn Drbg>, AlgoError> {
        self.find_by_name(name)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownDrbg))
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Drbg>, AlgoError> {
        self.find_by_oid(oid)
            .map(|row| row.create())
            .ok_or(AlgoError::new(ErrorKind::UnknownDrbg))
    }
}
