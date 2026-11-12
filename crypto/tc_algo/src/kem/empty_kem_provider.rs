use core::iter;

use tc_asn1::Asn1Oid;

use crate::kem::{Kem, KemEntry, KemProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptyKemProvider;

impl KemProvider for EmptyKemProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KemEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Kem>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownKem))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Kem>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownKem))
    }
}
