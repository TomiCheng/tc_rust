use core::iter;

use tc_asn1::Asn1Oid;

use crate::{KeyGenerator, KeyGeneratorEntry, KeyGeneratorProvider};

pub(crate) struct EmptyKeyGeneratorProvider;

impl KeyGeneratorProvider for EmptyKeyGeneratorProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyGeneratorEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Option<Box<dyn KeyGenerator>> {
        None
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Option<Box<dyn KeyGenerator>> {
        None
    }
}
