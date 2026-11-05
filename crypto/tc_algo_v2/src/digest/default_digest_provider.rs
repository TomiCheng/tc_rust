use tc_asn1::Asn1Oid;

use crate::digest::{Digest, DigestEntry, DigestProvider};

// The rows come in lookup order: a lookup takes the first that matches
pub(crate) struct DefaultDigestProvider {
    rows: Vec<Box<dyn DigestEntry>>,
}

impl DefaultDigestProvider {
    pub(crate) fn new(rows: Vec<Box<dyn DigestEntry>>) -> Self {
        Self { rows }
    }
}

impl DigestProvider for DefaultDigestProvider {
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DigestEntry> + '_> {
        Box::new(self.rows.iter().map(|row| row.as_ref() as &dyn DigestEntry))
    }

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Digest>> {
        let row = self.rows.iter().find(|row| {
            row.name().eq_ignore_ascii_case(name)
                || row
                    .aliases()
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(name))
        })?;
        Some(row.create())
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Digest>> {
        let row = self.rows.iter().find(|row| row.oids().contains(oid))?;
        Some(row.create())
    }
}
