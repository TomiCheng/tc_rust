use std::collections::HashSet;

// Which algorithms an Algo lists: a name in deny is left out, and when allow is not empty so is a
// name outside it. Getting an algorithm by name or OID does not look at this, so it does not forbid
// anything
#[derive(Clone, Debug, Default)]
pub struct Policy {
    // In upper case, so that names match without regard to ASCII case
    allow: HashSet<String>,
    deny: HashSet<String>,
}

impl Policy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_allow(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allow = normalized(names);
        self
    }

    pub fn with_deny(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.deny = normalized(names);
        self
    }

    pub fn allow(&self) -> &HashSet<String> {
        &self.allow
    }

    pub fn deny(&self) -> &HashSet<String> {
        &self.deny
    }

    // Takes every name of a row, so that a rule written with an alias still finds it
    pub(crate) fn lists(&self, names: &[impl AsRef<str>]) -> bool {
        !holds(&self.deny, names) && (self.allow.is_empty() || holds(&self.allow, names))
    }

    // For rows that decide for themselves whether a rule names them, as a cipher does for AES/CBC/*
    pub(crate) fn lists_by(&self, names_row: impl Fn(&str) -> bool) -> bool {
        let named = |set: &HashSet<String>| set.iter().any(|rule| names_row(rule));
        !named(&self.deny) && (self.allow.is_empty() || named(&self.allow))
    }
}

fn normalized(names: impl IntoIterator<Item = impl Into<String>>) -> HashSet<String> {
    names
        .into_iter()
        .map(|name| name.into().to_ascii_uppercase())
        .collect()
}

fn holds(set: &HashSet<String>, names: &[impl AsRef<str>]) -> bool {
    names
        .iter()
        .any(|name| set.contains(&name.as_ref().to_ascii_uppercase()))
}
