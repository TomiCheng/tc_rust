use std::sync::Arc;

use tc_asn1::Asn1Oid;

use crate::policy::BaseOf;
use crate::{EntryBase, Policy};

// What every provider of DefaultAlgo does with its rows, which come in lookup order: a lookup takes
// the first that matches
pub(crate) struct DefaultProvider<E: ?Sized> {
    rows: Vec<Box<E>>,
    policy: Option<Arc<dyn Policy>>,
}

impl<E: EntryBase + ?Sized> DefaultProvider<E> {
    pub(crate) fn new(rows: Vec<Box<E>>, policy: Option<Arc<dyn Policy>>) -> Self {
        Self { rows, policy }
    }

    // Asks the policy on every call and keeps no answer, since the caller's policy may change them
    pub(crate) fn listed(&self) -> impl Iterator<Item = &E> + '_ {
        self.rows
            .iter()
            .map(|row| row.as_ref())
            .filter(|row| self.is_listed(row))
    }

    fn is_listed(&self, row: &E) -> bool {
        self.policy
            .as_ref()
            .is_none_or(|policy| policy.filter(&BaseOf(row)))
    }

    pub(crate) fn find_by_name(&self, name: &str) -> Option<&E> {
        let row = self.rows.iter().find(|row| row.matches_name(name))?;
        Some(row.as_ref())
    }

    pub(crate) fn find_by_oid(&self, oid: &Asn1Oid) -> Option<&E> {
        let row = self.rows.iter().find(|row| row.oids().contains(oid))?;
        Some(row.as_ref())
    }
}
