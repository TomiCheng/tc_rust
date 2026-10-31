use core::fmt;

use rand_core::CryptoRng;
use tc_asn1::NamedOid;

use super::{KeyGenParams, KeyGenerator};
use crate::AlgoError;
use crate::params::SecretKey;

pub(super) type CheckParams = fn(&KeyGenParams) -> Result<(), AlgoError>;
pub(super) type GenerateKey = fn(&KeyGenParams, &mut dyn CryptoRng) -> Result<SecretKey, AlgoError>;

#[derive(Clone, Debug)]
pub struct KeyGeneratorEntry {
    // The first is the canonical name, the rest are aliases
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    // What generate uses until init is called; None makes init required, as for a generator with no size of its own
    default_params: Option<KeyGenParams>,
    // Whether init takes these params; the values themselves are checked when generating
    check_params: CheckParams,
    generate: GenerateKey,
}

impl KeyGeneratorEntry {
    #[allow(
        dead_code,
        reason = "the table is empty when every symmetric key feature is off"
    )]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        default_params: Option<KeyGenParams>,
        check_params: CheckParams,
        generate: GenerateKey,
    ) -> Self {
        Self {
            names,
            oids,
            default_params,
            check_params,
            generate,
        }
    }

    pub fn name(&self) -> &'static str {
        self.names[0]
    }

    pub(super) fn names(&self) -> &'static [&'static str] {
        self.names
    }

    pub fn oids(&self) -> &'static [NamedOid] {
        self.oids
    }

    pub fn generator(&'static self) -> KeyGenerator {
        KeyGenerator::new(self)
    }

    pub(super) fn default_params(&self) -> Option<&KeyGenParams> {
        self.default_params.as_ref()
    }

    pub(super) fn check_params(&self, params: &KeyGenParams) -> Result<(), AlgoError> {
        (self.check_params)(params)
    }

    pub(super) fn generate(
        &self,
        params: &KeyGenParams,
        rng: &mut dyn CryptoRng,
    ) -> Result<SecretKey, AlgoError> {
        (self.generate)(params, rng)
    }
}

// The canonical name, followed by the OIDs when there are any, e.g. `AES128  [id-aes128-ECB, ...]`
impl fmt::Display for KeyGeneratorEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())?;
        if let Some((first, rest)) = self.oids.split_first() {
            write!(f, "  [{}", first.name())?;
            for oid in rest {
                write!(f, ", {}", oid.name())?;
            }
            f.write_str("]")?;
        }
        Ok(())
    }
}
