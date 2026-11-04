use std::sync::OnceLock;

use tc_asn1::Asn1Oid;

use super::table::KEY_GENERATORS;
use super::{KeyGenerator, KeyGeneratorEntry};
use crate::params::SecretKey;
use crate::{AlgoError, ErrorKind, Policy};

/// Key generators by name or OID, after Bouncy Castle's `GeneratorUtilities`, from
/// [`Algo::key_generator`](crate::Algo::key_generator): each makes a [`SecretKey`] for the
/// algorithms that take one, such as AES. The operation's parameters, such as an IV, come from the
/// factory of the algorithm that uses them.
#[derive(Clone, Copy, Debug)]
pub struct KeyGeneratorFactory<'a> {
    policy: &'a Policy,
    // Filtered from the table on the first call of algorithms after a policy is set
    listed: &'a OnceLock<Vec<&'static KeyGeneratorEntry>>,
}

impl<'a> KeyGeneratorFactory<'a> {
    pub(crate) fn new(
        policy: &'a Policy,
        listed: &'a OnceLock<Vec<&'static KeyGeneratorEntry>>,
    ) -> Self {
        Self { policy, listed }
    }

    pub fn algorithms(self) -> impl Iterator<Item = &'static KeyGeneratorEntry> {
        self.listed
            .get_or_init(|| {
                KEY_GENERATORS
                    .iter()
                    .filter(|entry| self.policy.lists(entry.names()))
                    .collect()
            })
            .iter()
            .copied()
    }

    // Names match without regard to ASCII case; a string that is not a name is parsed as a dotted
    // OID, as in Bouncy Castle
    pub fn get_by_name(self, name: &str) -> Result<KeyGenerator, AlgoError> {
        find(name)
            .map(KeyGeneratorEntry::generator)
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
    }

    pub fn get_by_oid(self, oid: &Asn1Oid) -> Result<KeyGenerator, AlgoError> {
        find_by_oid(oid)
            .map(KeyGeneratorEntry::generator)
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
    }

    // Finds the generator by name and makes one key with its defaults and the operating system's
    // randomness
    pub fn generate(self, name: &str) -> Result<SecretKey, AlgoError> {
        self.get_by_name(name)?.generate()
    }
}

fn find(name: &str) -> Option<&'static KeyGeneratorEntry> {
    KEY_GENERATORS
        .iter()
        .find(|entry| matches_name(entry.names(), name))
        .or_else(|| find_by_oid(&name.parse().ok()?))
}

fn matches_name(names: &[&str], name: &str) -> bool {
    names.iter().any(|known| known.eq_ignore_ascii_case(name))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static KeyGeneratorEntry> {
    KEY_GENERATORS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
