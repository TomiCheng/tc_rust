use core::iter;

use tc_asn1::Asn1Oid;

use crate::{AlgoError, ErrorKind, KeyGenerator, KeyGeneratorEntry, KeyGeneratorProvider};

pub(crate) struct EmptyKeyGeneratorProvider;

impl KeyGeneratorProvider for EmptyKeyGeneratorProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyGeneratorEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn KeyGenerator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownGenerator))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn KeyGenerator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownGenerator))
    }
}
