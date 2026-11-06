use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::{KeyGenerator, KeyGeneratorEntry, KeyGeneratorProvider};

impl KeyGeneratorProvider for DefaultProvider<dyn KeyGeneratorEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn KeyGeneratorEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn KeyGeneratorEntry))
    }

    fn get_by_name(&self, name: &str) -> Option<Box<dyn KeyGenerator>> {
        Some(self.find_by_name(name)?.create())
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn KeyGenerator>> {
        Some(self.find_by_oid(oid)?.create())
    }
}
