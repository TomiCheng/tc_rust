use tc_asn1::Asn1Oid;

use crate::default_provider::DefaultProvider;
use crate::{Wrapper, WrapperEntry, WrapperProvider};

impl WrapperProvider for DefaultProvider<dyn WrapperEntry> {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn WrapperEntry> + '_> {
        Box::new(self.listed().map(|row| row as &dyn WrapperEntry))
    }

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Wrapper>> {
        Some(self.find_by_name(name)?.create())
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Wrapper>> {
        Some(self.find_by_oid(oid)?.create())
    }
}
