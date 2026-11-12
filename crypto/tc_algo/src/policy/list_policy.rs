use std::collections::HashSet;

use crate::{EntryBase, Policy};

// An allow list and a deny list of names. A row named in deny is left out, and when allow is not
// empty so is a row not named in it. A rule finds a row by its name or an alias, without regard to
// ASCII case
#[derive(Clone, Debug, Default)]
pub struct ListPolicy {
    allow: HashSet<String>,
    deny: HashSet<String>,
}

impl ListPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_allow(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allow = names.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_deny(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.deny = names.into_iter().map(Into::into).collect();
        self
    }

    pub fn allow(&self) -> &HashSet<String> {
        &self.allow
    }

    pub fn deny(&self) -> &HashSet<String> {
        &self.deny
    }
}

impl Policy for ListPolicy {
    fn filter(&self, entry: &dyn EntryBase) -> bool {
        !names(&self.deny, entry) && (self.allow.is_empty() || names(&self.allow, entry))
    }
}

fn names(rules: &HashSet<String>, entry: &dyn EntryBase) -> bool {
    rules.iter().any(|rule| {
        entry.name().eq_ignore_ascii_case(rule)
            || entry
                .aliases()
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(rule))
    })
}
