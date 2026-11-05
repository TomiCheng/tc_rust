use core::iter;

use tc_asn1::Asn1Oid;

use crate::{Cipher, CipherEntry, CipherProvider};

pub(crate) struct EmptyCipherProvider;

impl CipherProvider for EmptyCipherProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn CipherEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Option<Box<dyn Cipher>> {
        None
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Option<Box<dyn Cipher>> {
        None
    }
}
