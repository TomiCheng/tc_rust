use tc_asn1::Asn1Oid;

use crate::{AlgoError, ErrorKind, KeyPair, KeyPairGenerator, KeyPairGeneratorEntry};

pub trait KeyPairGeneratorProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyPairGeneratorEntry> + '_>;

    fn get_by_name(&self, name: &str) -> Option<Box<dyn KeyPairGenerator>>;

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn KeyPairGenerator>>;

    fn generate_by_name(&self, name: &str) -> Result<KeyPair, AlgoError> {
        self.get_by_name(name)
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))?
            .generate()
    }

    fn generate_by_oid(&self, oid: &Asn1Oid) -> Result<KeyPair, AlgoError> {
        self.get_by_oid(oid)
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))?
            .generate()
    }
}
