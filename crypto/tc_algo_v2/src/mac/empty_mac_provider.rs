use core::iter;

use tc_asn1::Asn1Oid;

use crate::{AlgoError, ErrorKind, Mac, MacEntry, MacProvider};

pub(crate) struct EmptyMacProvider;

impl MacProvider for EmptyMacProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn MacEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Mac>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownMac))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Mac>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownMac))
    }
}
