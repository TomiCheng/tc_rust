use tc_asn1::Asn1Oid;

use crate::{AlgoError, KeyGenerator, KeyGeneratorEntry, Params};

pub trait KeyGeneratorProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyGeneratorEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn KeyGenerator>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn KeyGenerator>, AlgoError>;

    fn generate_by_name(&self, name: &str) -> Result<Box<dyn Params>, AlgoError> {
        self.get_by_name(name)?.generate()
    }

    fn generate_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn Params>, AlgoError> {
        self.get_by_oid(oid)?.generate()
    }

    fn generate_by_name_with(
        &self,
        name: &str,
        params: &dyn Params,
    ) -> Result<Box<dyn Params>, AlgoError> {
        let mut generator = self.get_by_name(name)?;
        generator.init(params)?;
        generator.generate()
    }

    fn generate_by_oid_with(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
    ) -> Result<Box<dyn Params>, AlgoError> {
        let mut generator = self.get_by_oid(oid)?;
        generator.init(params)?;
        generator.generate()
    }
}
