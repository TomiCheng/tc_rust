use core::fmt;

use rand_core::CryptoRng;

use super::{KeyGenParams, KeyGeneratorEntry};
use crate::AlgoError;
use crate::params::SecretKey;

// Calling init is optional: without it the generator uses the defaults of its entry, as in
// Bouncy Castle. The randomness is the operating system's unless with_rng supplies another
pub struct KeyGenerator {
    entry: &'static KeyGeneratorEntry,
    params: Option<KeyGenParams>,
    rng: Box<dyn CryptoRng + Send>,
}

impl KeyGenerator {
    pub fn entry(&self) -> &'static KeyGeneratorEntry {
        todo!()
    }

    pub fn with_rng(&mut self, rng: impl CryptoRng + Send + 'static) -> &mut Self {
        todo!()
    }

    pub fn init(&mut self, params: impl Into<KeyGenParams>) -> Result<(), AlgoError> {
        todo!()
    }

    pub fn generate(&mut self) -> Result<SecretKey, AlgoError> {
        todo!()
    }
}

// Shows the generator's name, never its randomness
impl fmt::Debug for KeyGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
