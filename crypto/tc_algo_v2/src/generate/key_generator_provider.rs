use tc_asn1::Asn1Oid;

use crate::{AlgoError, ErrorKind, KeyGenerator, KeyGeneratorEntry, Params};

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

    fn generate_by_name_with(
        &self,
        name: &str,
        params: &dyn Params,
    ) -> Result<Box<dyn Params>, AlgoError> {
        let mut generator = self
            .get_by_name(name)
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))?;
        generator.init(params)?;
        generator.generate()
    }

    fn generate_by_oid_with(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
    ) -> Result<Box<dyn Params>, AlgoError> {
        let mut generator = self
            .get_by_oid(oid)
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))?;
        generator.init(params)?;
        generator.generate()
    }
}
