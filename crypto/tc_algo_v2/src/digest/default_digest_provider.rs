use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::digest::{Digest, DigestEntry, DigestProvider};

impl DigestProvider for DefaultProvider<dyn DigestEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DigestEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn DigestEntry))
    }

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Digest>> {
        Some(self.find_by_name(name)?.create())
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Digest>> {
        Some(self.find_by_oid(oid)?.create())
    }
}
