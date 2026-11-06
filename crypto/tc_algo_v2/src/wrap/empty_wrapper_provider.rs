use core::iter;

use tc_asn1::Asn1Oid;

use crate::{Wrapper, WrapperEntry, WrapperProvider};

pub(crate) struct EmptyWrapperProvider;

impl WrapperProvider for EmptyWrapperProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn WrapperEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Option<Box<dyn Wrapper>> {
        None
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Option<Box<dyn Wrapper>> {
        None
    }
}
