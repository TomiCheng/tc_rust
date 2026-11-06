use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::{Mac, MacEntry, MacProvider};

impl MacProvider for DefaultProvider<dyn MacEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn MacEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn MacEntry))
    }

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Mac>> {
        Some(self.find_by_name(name)?.create())
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Mac>> {
        Some(self.find_by_oid(oid)?.create())
    }
}
