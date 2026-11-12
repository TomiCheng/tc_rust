use core::fmt;

use rand::rngs::SysRng;
use rand_core::{CryptoRng, UnwrapErr};

use super::{KeyPair, KeyPairGeneratorEntry};
use crate::generate::KeyGenParams;
use crate::{AlgoError, ErrorKind};

// Calling init is optional: without it the generator uses the defaults of its entry, as in
// Bouncy Castle. The randomness is the operating system's unless with_rng supplies another
pub struct KeyPairGenerator {
    entry: &'static KeyPairGeneratorEntry,
    params: Option<KeyGenParams>,
    rng: Box<dyn CryptoRng + Send>,
}

impl KeyPairGenerator {
    pub(super) fn new(entry: &'static KeyPairGeneratorEntry) -> Self {
        Self {
            entry,
            params: entry.default_params().cloned(),
            rng: Box::new(UnwrapErr(SysRng)),
        }
    }

    pub fn entry(&self) -> &'static KeyPairGeneratorEntry {
        self.entry
    }

    pub fn with_rng(&mut self, rng: impl CryptoRng + Send + 'static) -> &mut Self {
        self.rng = Box::new(rng);
        self
    }

    // Takes params of a kind this generator accepts and keeps the current ones otherwise; the
    // values are checked when generating, by the algorithm underneath
    pub fn init(&mut self, params: impl Into<KeyGenParams>) -> Result<(), AlgoError> {
        let params = params.into();
        self.entry.check_params(&params)?;
        self.params = Some(params);
        Ok(())
    }

    pub fn generate(&mut self) -> Result<KeyPair, AlgoError> {
        let params = self
            .params
            .as_ref()
            .ok_or(AlgoError::new(ErrorKind::InvalidKeyGenParams))?;
        self.entry.generate(params, &mut *self.rng)
    }
}

// Shows the generator's name, never its randomness
impl fmt::Debug for KeyPairGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPairGenerator")
            .field("name", &self.entry.name())
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}
