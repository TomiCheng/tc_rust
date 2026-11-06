use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::{Xof, XofEntry, XofProvider};

impl XofProvider for DefaultProvider<dyn XofEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn XofEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn XofEntry))
    }

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Xof>> {
        Some(self.find_by_name(name)?.create())
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Xof>> {
        Some(self.find_by_oid(oid)?.create())
    }
}
