use std::sync::OnceLock;

use tc_asn1::Asn1Oid;

use super::table::KEY_PAIR_GENERATORS;
use super::{KeyPair, KeyPairGenerator, KeyPairGeneratorEntry};
use crate::{AlgoError, ErrorKind, Policy};

/// Key pair generators by name or OID, after Bouncy Castle's `GeneratorUtilities`, from
/// [`Algo::key_pair_generator`](crate::Algo::key_pair_generator): each makes a [`KeyPair`] of a
/// public and a private key, such as for RSA or DH.
///
/// ```no_run
/// # #[cfg(feature = "rsa")] {
/// use tc_algo_old::{Algo, AnyKeyParams, AnyParams, KeyGenParams};
///
/// let algo = Algo::new();
///
/// // Find the generator by name; without init it makes 2048-bit keys with exponent 65537
/// let mut generator = algo.key_pair_generator().get_by_name("RSA")?;
///
/// // init changes the parameters: rsa() starts at the defaults, and each with_ changes one
/// generator.init(KeyGenParams::rsa().with_bits(2048))?;
///
/// // Generate the pair, then hand each key to the factory that uses it: the public key to
/// // encrypt or verify, the private key to decrypt or sign
/// let pair = generator.generate()?;
/// let public = AnyParams::new(AnyKeyParams::Public(pair.public));
/// let private = AnyParams::new(AnyKeyParams::Private(pair.private));
/// # }
/// # Ok::<(), tc_algo_old::AlgoError>(())
/// ```
///
/// `algo.key_pair_generator().generate("RSA")?` does the same in one step with the defaults.
#[derive(Clone, Copy, Debug)]
pub struct KeyPairGeneratorFactory<'a> {
    policy: &'a Policy,
    // Filtered from the table on the first call of algorithms after a policy is set
    listed: &'a OnceLock<Vec<&'static KeyPairGeneratorEntry>>,
}

impl<'a> KeyPairGeneratorFactory<'a> {
    pub(crate) fn new(
        policy: &'a Policy,
        listed: &'a OnceLock<Vec<&'static KeyPairGeneratorEntry>>,
    ) -> Self {
        Self { policy, listed }
    }

    pub fn algorithms(self) -> impl Iterator<Item = &'static KeyPairGeneratorEntry> {
        self.listed
            .get_or_init(|| {
                KEY_PAIR_GENERATORS
                    .iter()
                    .filter(|entry| self.policy.lists(entry.names()))
                    .collect()
            })
            .iter()
            .copied()
    }

    // Names match without regard to ASCII case; a string that is not a name is parsed as a dotted
    // OID, as in Bouncy Castle
    pub fn get_by_name(self, name: &str) -> Result<KeyPairGenerator, AlgoError> {
        find(name)
            .map(KeyPairGeneratorEntry::generator)
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
    }

    pub fn get_by_oid(self, oid: &Asn1Oid) -> Result<KeyPairGenerator, AlgoError> {
        find_by_oid(oid)
            .map(KeyPairGeneratorEntry::generator)
            .ok_or(AlgoError::new(ErrorKind::UnknownGenerator))
    }

    // Finds the generator by name and makes one key pair with its defaults and the operating
    // system's randomness; a generator without defaults, such as DH's, fails
    pub fn generate(self, name: &str) -> Result<KeyPair, AlgoError> {
        self.get_by_name(name)?.generate()
    }
}

fn find(name: &str) -> Option<&'static KeyPairGeneratorEntry> {
    KEY_PAIR_GENERATORS
        .iter()
        .find(|entry| matches_name(entry.names(), name))
        .or_else(|| find_by_oid(&name.parse().ok()?))
}

fn matches_name(names: &[&str], name: &str) -> bool {
    names.iter().any(|known| known.eq_ignore_ascii_case(name))
}

fn find_by_oid(oid: &Asn1Oid) -> Option<&'static KeyPairGeneratorEntry> {
    KEY_PAIR_GENERATORS
        .iter()
        .find(|entry| entry.oids().iter().any(|known| *known == *oid))
}
