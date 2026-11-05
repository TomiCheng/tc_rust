use std::sync::Arc;

use tc_asn1::Asn1Oid;

use crate::Policy;
use crate::digest::{Digest, DigestEntry, DigestProvider};
use crate::policy::BaseOf;

// The rows come in lookup order: a lookup takes the first that matches
pub(crate) struct DefaultDigestProvider {
    rows: Vec<Box<dyn DigestEntry>>,
    policy: Option<Arc<dyn Policy>>,
}

impl DefaultDigestProvider {
    pub(crate) fn new(rows: Vec<Box<dyn DigestEntry>>, policy: Option<Arc<dyn Policy>>) -> Self {
        Self { rows, policy }
    }

    fn is_listed(&self, row: &dyn DigestEntry) -> bool {
        self.policy
            .as_ref()
            .is_none_or(|policy| policy.filter(&BaseOf(row)))
    }
}

impl DigestProvider for DefaultDigestProvider {
    // Asks the policy on every call and keeps no answer, since the caller's policy may change them
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn DigestEntry> + '_> {
        Box::new(
            self.rows
                .iter()
                .map(|row| row.as_ref() as &dyn DigestEntry)
                .filter(|row| self.is_listed(*row)),
        )
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
