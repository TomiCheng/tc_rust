use tc_asn1::Asn1Oid;

use super::{KeyGenerator, KeyGeneratorEntry, Params};
use crate::{AlgoError, ErrorKind};

pub trait KeyGeneratorProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyGeneratorEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Option<Box<dyn KeyGenerator>>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn KeyGenerator>>;

    fn generate_by_name(&self, name: &str) -> Result<Box<dyn Params>, AlgoError> {
        self.get_by_name(name)
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))?
            .generate()
    }

    fn generate_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Params>, AlgoError> {
        self.get_by_oid(oid)
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))?
            .generate()
    }
}
