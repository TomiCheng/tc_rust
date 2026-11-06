use core::iter;

use tc_asn1::Asn1Oid;

use crate::{AlgoError, ErrorKind, Xof, XofEntry, XofProvider};

pub(crate) struct EmptyXofProvider;

impl XofProvider for EmptyXofProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn XofEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Xof>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownXof))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Xof>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownXof))
    }
}
