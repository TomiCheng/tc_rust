use std::sync::Arc;

use tc_asn1::Asn1Oid;

use crate::policy::BaseOf;
use crate::{Policy, Wrapper, WrapperEntry, WrapperProvider};

// The rows come in lookup order: a lookup takes the first that matches
pub(crate) struct DefaultWrapperProvider {
    rows: Vec<Box<dyn WrapperEntry>>,
    policy: Option<Arc<dyn Policy>>,
}

impl DefaultWrapperProvider {
    pub(crate) fn new(rows: Vec<Box<dyn WrapperEntry>>, policy: Option<Arc<dyn Policy>>) -> Self {
        Self { rows, policy }
    }

    fn is_listed(&self, row: &dyn WrapperEntry) -> bool {
        self.policy
            .as_ref()
            .is_none_or(|policy| policy.filter(&BaseOf(row)))
    }
}

impl WrapperProvider for DefaultWrapperProvider {
    // Asks the policy on every call and keeps no answer, since the caller's policy may change them
    fn algorithms(&self) -> Box<dyn Iterator<Item = &dyn WrapperEntry> + '_> {
        Box::new(
            self.rows
                .iter()
                .map(|row| row.as_ref() as &dyn WrapperEntry)
                .filter(|row| self.is_listed(*row)),
        )
    }

    fn get_by_name(&self, name: &str) -> Option<Box<dyn Wrapper>> {
        let row = self.rows.iter().find(|row| {
            row.name().eq_ignore_ascii_case(name)
                || row
                    .aliases()
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(name))
        })?;
        Some(row.create())
    }

    fn get_by_oid(&self, oid: &Asn1Oid) -> Option<Box<dyn Wrapper>> {
        let row = self.rows.iter().find(|row| row.oids().contains(oid))?;
        Some(row.create())
    }
}
