use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;

use super::random::{Rule, random_key};
use crate::generate::{KeyGenerator, KeyGeneratorEntry};
use crate::params::{generate::KeyLength, key::KeyOwned};
use crate::{AlgoError, EntryBase, ErrorKind, Params};

// These rows generate a key of the default length. Rows with multiple supported lengths
// also accept a KeyLength in init.

// The lengths in bytes that the cipher of a row takes, as its engine checks them
#[derive(Clone, Copy)]
pub(super) enum Lengths {
    // These alone
    #[allow(dead_code, reason = "a feature may have rows of ranges alone")]
    Of(&'static [usize]),
    // From min to max, both in, by step
    #[allow(dead_code, reason = "a feature may have rows of fixed lengths alone")]
    Range { min: usize, max: usize, step: usize },
}

impl Lengths {
    #[allow(dead_code, reason = "a feature may have rows of fixed lengths alone")]
    pub(super) const fn range(min: usize, max: usize) -> Self {
        Self::Range { min, max, step: 1 }
    }

    pub(super) fn allows(self, len: usize) -> bool {
        match self {
            Self::Of(lens) => lens.contains(&len),
            Self::Range { min, max, step } => (min..=max).contains(&len) && (len - min) % step == 0,
        }
    }
}

// The length of a KeyLength that `lengths` allows, or InvalidParams
pub(super) fn key_length(params: &dyn Params, lengths: Lengths) -> Result<usize, AlgoError> {
    params
        .as_any()
        .downcast_ref::<KeyLength>()
        .map(KeyLength::bytes)
        .filter(|len| lengths.allows(*len))
        .ok_or(AlgoError::new(ErrorKind::InvalidParams))
}

pub(super) fn row(
    name: &'static str,
    aliases: &[&'static str],
    oids: &[&str],
    key_len: usize,
    lengths: Lengths,
    rule: Rule,
    rand: fn() -> Box<dyn CryptoRng>,
) -> Box<dyn KeyGeneratorEntry> {
    debug_assert!(lengths.allows(key_len), "{name}");
    Box::new(Row {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        key_len,
        lengths,
        rule,
        rand,
    })
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    key_len: usize,
    lengths: Lengths,
    rule: Rule,
    rand: fn() -> Box<dyn CryptoRng>,
}

impl EntryBase for Row {
    fn name(&self) -> &str {
        self.name
    }

    fn aliases(&self) -> &[String] {
        &self.aliases
    }

    fn oids(&self) -> &[Asn1Oid] {
        &self.oids
    }
}

impl KeyGeneratorEntry for Row {
    fn create(&self) -> Box<dyn KeyGenerator> {
        Box::new(FixedKeyGenerator {
            key_len: self.key_len,
            lengths: self.lengths,
            rule: self.rule,
            rand: (self.rand)(),
        })
    }
}

// A KeyOwned of the row's length, or of that of the last init that succeeded
struct FixedKeyGenerator {
    key_len: usize,
    lengths: Lengths,
    rule: Rule,
    rand: Box<dyn CryptoRng>,
}

impl KeyGenerator for FixedKeyGenerator {
    fn init(&mut self, params: &dyn Params) -> Result<(), AlgoError> {
        if matches!(self.lengths, Lengths::Of([_])) {
            return Err(AlgoError::new(ErrorKind::InvalidParams));
        }
        self.key_len = key_length(params, self.lengths)?;
        Ok(())
    }

    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let key = random_key(self.rand.as_mut(), self.key_len, self.rule);
        Ok(Box::new(KeyOwned::new(key)))
    }
}
