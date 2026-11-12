use tc_asn1::Asn1Oid;

use crate::EntryBase;

// What a Policy sees of a row. A `&dyn DigestEntry` cannot become a `&dyn EntryBase` by itself until
// Rust 1.86, which is past this crate's MSRV
pub(crate) struct BaseOf<'a, T: EntryBase + ?Sized>(pub(crate) &'a T);

impl<T: EntryBase + ?Sized> EntryBase for BaseOf<'_, T> {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn aliases(&self) -> &[String] {
        self.0.aliases()
    }

    fn oids(&self) -> &[Asn1Oid] {
        self.0.oids()
    }
}
