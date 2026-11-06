use core::iter;

use tc_asn1::Asn1Oid;

use crate::pbe::{Pbe, PbeEntry, PbeProvider};
use crate::{AlgoError, ErrorKind};

pub(crate) struct EmptyPbeProvider;

impl PbeProvider for EmptyPbeProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn PbeEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Pbe>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownPbe))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Pbe>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownPbe))
    }
}
