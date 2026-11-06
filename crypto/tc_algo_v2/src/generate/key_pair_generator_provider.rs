use tc_asn1::Asn1Oid;

use crate::{AlgoError, KeyPair, KeyPairGenerator, KeyPairGeneratorEntry};

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
}
