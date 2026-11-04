use core::iter;

use tc_asn1::Asn1Oid;

use crate::{KeyPairGenerator, KeyPairGeneratorEntry, KeyPairGeneratorProvider};

pub(crate) struct EmptyKeyPairGeneratorProvider;

impl KeyPairGeneratorProvider for EmptyKeyPairGeneratorProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyPairGeneratorEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Option<Box<dyn KeyPairGenerator>> {
        None
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Option<Box<dyn KeyPairGenerator>> {
        None
    }
}
