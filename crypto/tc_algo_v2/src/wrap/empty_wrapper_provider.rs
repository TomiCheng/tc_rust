use core::iter;

use tc_asn1::Asn1Oid;

use crate::{AlgoError, ErrorKind, Wrapper, WrapperEntry, WrapperProvider};

pub(crate) struct EmptyWrapperProvider;

impl WrapperProvider for EmptyWrapperProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn WrapperEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Result<Box<dyn Wrapper>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownWrapper))
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Result<Box<dyn Wrapper>, AlgoError> {
        Err(AlgoError::new(ErrorKind::UnknownWrapper))
    }
}
