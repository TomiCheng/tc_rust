use core::iter;

use tc_asn1::Asn1Oid;

use crate::kem::{Decapsulator, Encapsulator, KemEntry, KemProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptyKemProvider;

impl KemProvider for EmptyKemProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KemEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_encapsulator_by_name(&self, _name: &str) -> Result<Box<dyn Encapsulator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownKem))
    }

    fn get_encapsulator_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Encapsulator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownKem))
    }

    fn get_decapsulator_by_name(&self, _name: &str) -> Result<Box<dyn Decapsulator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownKem))
    }

    fn get_decapsulator_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Decapsulator>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownKem))
    }
}
