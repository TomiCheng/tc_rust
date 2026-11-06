use tc_asn1::Asn1Oid;

use crate::cipher::{Cipher, CipherEntry, CipherProvider};
use crate::default_provider::DefaultProvider;

impl CipherProvider for DefaultProvider<dyn CipherEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn CipherEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn CipherEntry))
    }

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Cipher>> {
        Some(self.find_by_name(name)?.create())
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Cipher>> {
        Some(self.find_by_oid(oid)?.create())
    }
}
