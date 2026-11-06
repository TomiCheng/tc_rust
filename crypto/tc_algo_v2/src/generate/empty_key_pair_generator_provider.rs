use core::iter;

use tc_asn1::Asn1Oid;

use crate::generate::{KeyPairGenerator, KeyPairGeneratorEntry, KeyPairGeneratorProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptyKeyPairGeneratorProvider;

impl KeyPairGeneratorProvider for EmptyKeyPairGeneratorProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyPairGeneratorEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn KeyPairGenerator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownGenerator))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn KeyPairGenerator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownGenerator))
    }
}
