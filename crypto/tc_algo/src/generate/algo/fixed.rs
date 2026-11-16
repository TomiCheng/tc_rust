use rand_core::CryptoRng;
use tc_asn1::Asn1Oid;

use crate::generate::{KeyGenerator, KeyGeneratorEntry};
use crate::params::KeyOwned;
use crate::{AlgoError, EntryBase, Params};

// A row of a key of fixed length, as the block and stream ciphers have
// What a key must keep to besides being random: DES and DESede, as Bouncy Castle's DesKeyGenerator
// and DesEdeKeyGenerator, set the parity bits and draw again for a weak key, and for DESede again
// for a key whose parts repeat, which is DES in disguise
#[derive(Clone, Copy)]
pub(super) enum Rule {
    #[allow(dead_code, reason = "unused when only DES or DESede is on")]
    Random,
    #[cfg(feature = "des")]
    Des,
    #[cfg(feature = "desede")]
    DesEde,
}

pub(super) fn row(
    name: &'static str,
    aliases: &[&'static str],
    oids: &[&str],
    key_len: usize,
    rule: Rule,
    rand: fn() -> Box<dyn CryptoRng>,
) -> Box<dyn KeyGeneratorEntry> {
    Box::new(Row {
        name,
        aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
        oids: oids
            .iter()
            .map(|dotted| dotted.parse().expect("a valid OID"))
            .collect(),
        key_len,
        rule,
        rand,
    })
}

struct Row {
    name: &'static str,
    aliases: Vec<String>,
    oids: Vec<Asn1Oid>,
    key_len: usize,
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
            rule: self.rule,
            rand: (self.rand)(),
        })
    }
}

// A key of the row's length, with no params to set
struct FixedKeyGenerator {
    key_len: usize,
    rule: Rule,
    rand: Box<dyn CryptoRng>,
}

impl KeyGenerator for FixedKeyGenerator {
    fn generate(&mut self) -> Result<Box<dyn Params>, AlgoError> {
        let mut key = vec![0; self.key_len];
        loop {
            self.rand.fill_bytes(&mut key);
            let done = match self.rule {
                Rule::Random => true,
                #[cfg(feature = "des")]
                Rule::Des => {
                    tc_des::set_odd_parity(&mut key);
                    !tc_des::is_weak_key(key.as_slice().try_into().expect("8 bytes"))
                }
                #[cfg(feature = "desede")]
                Rule::DesEde => {
                    tc_des::set_odd_parity(&mut key);
                    !tc_des::is_weak_ede_key(&key) && tc_des::is_real_ede_key(&key)
                }
            };
            if done {
                return Ok(Box::new(KeyOwned::new(key)));
            }
        }
    }
}
