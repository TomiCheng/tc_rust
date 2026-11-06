use core::iter;

use tc_asn1::Asn1Oid;

use crate::{Xof, XofEntry, XofProvider};

pub(crate) struct EmptyXofProvider;

impl XofProvider for EmptyXofProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn XofEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Option<Box<dyn Xof>> {
        None
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Option<Box<dyn Xof>> {
        None
    }
}
