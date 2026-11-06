use tc_asn1::Asn1Oid;

use crate::generate::{KeyPair, KeyPairGenerator, KeyPairGeneratorEntry};
use crate::{AlgoError, Params};

pub trait KeyPairGeneratorProvider: Send + Sync {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyPairGeneratorEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Result<Box<dyn KeyPairGenerator>, AlgoError>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Result<Box<dyn KeyPairGenerator>, AlgoError>;

    fn generate_by_name(&self, name: &str) -> Result<KeyPair, AlgoError> {
        self.get_by_name(name)?.generate()
    }

    fn generate_by_oid(&self, oid: &Asn1Oid) -> Result<KeyPair, AlgoError> {
        self.get_by_oid(oid)?.generate()
    }

    fn generate_by_name_with(&self, name: &str, params: &dyn Params) -> Result<KeyPair, AlgoError> {
        generate_with(self.get_by_name(name)?, params)
    }

    fn generate_by_oid_with(
        &self,
        oid: &Asn1Oid,
        params: &dyn Params,
    ) -> Result<KeyPair, AlgoError> {
        generate_with(self.get_by_oid(oid)?, params)
    }
}

fn generate_with(
    mut generator: Box<dyn KeyPairGenerator>,
    params: &dyn Params,
) -> Result<KeyPair, AlgoError> {
    generator.init(params)?;
    generator.generate()
}
