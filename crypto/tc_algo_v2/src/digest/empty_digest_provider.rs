use core::iter;

use tc_asn1::Asn1Oid;

use crate::{Digest, DigestEntry, DigestProvider};

pub(crate) struct EmptyDigestProvider;

impl DigestProvider for EmptyDigestProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DigestEntry> + '_> {
        Box::new(iter::empty())
    }

    fn get_by_name(&self, _name: &str) -> Option<Box<dyn Digest>> {
        None
    }

    fn get_by_oid(&self, _oid: &Asn1Oid) -> Option<Box<dyn Digest>> {
        None
    }
}
