use core::fmt;

use rand_core::CryptoRng;
use tc_asn1::NamedOid;

use super::{KeyGenParams, KeyPair, KeyPairGenerator};
use crate::AlgoError;

pub(super) type CheckParams = fn(&KeyGenParams) -> Result<(), AlgoError>;
pub(super) type GenerateKeyPair =
    fn(&KeyGenParams, &mut dyn CryptoRng) -> Result<KeyPair, AlgoError>;

#[derive(Clone, Debug)]
pub struct KeyPairGeneratorEntry {
    // The first is the canonical name, the rest are aliases
    names: &'static [&'static str],
    oids: &'static [NamedOid],
    // What generate uses until init is called; None makes init required, as for EC's curve
    default_params: Option<KeyGenParams>,
    // Whether init takes these params; the values themselves are checked when generating
    check_params: CheckParams,
    generate: GenerateKeyPair,
}

impl KeyPairGeneratorEntry {
    #[allow(
        dead_code,
        reason = "the table is empty when every key pair feature is off"
    )]
    pub(super) const fn new(
        names: &'static [&'static str],
        oids: &'static [NamedOid],
        default_params: Option<KeyGenParams>,
        check_params: CheckParams,
        generate: GenerateKeyPair,
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

    pub fn generator(&'static self) -> KeyPairGenerator {
        KeyPairGenerator::new(self)
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
    ) -> Result<KeyPair, AlgoError> {
        (self.generate)(params, rng)
    }
}

// The canonical name, followed by the OIDs when there are any, e.g. `RSA  [rsaEncryption]`
impl fmt::Display for KeyPairGeneratorEntry {
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
