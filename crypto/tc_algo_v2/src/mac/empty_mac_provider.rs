use core::iter;

use tc_asn1::Asn1Oid;

use crate::{Mac, MacEntry, MacProvider};

pub(crate) struct EmptyMacProvider;

impl MacProvider for EmptyMacProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn MacEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Option<Box<dyn Mac>> {
        None
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Option<Box<dyn Mac>> {
        None
    }
}
