use core::fmt;

use rand_core::CryptoRng;

use super::KeyPair;
use super::{KeyGenParams, KeyPairGeneratorEntry};
use crate::AlgoError;

// Calling init is optional: without it the generator uses the defaults of its entry, as in
// Bouncy Castle. The randomness is the operating system's unless with_rng supplies another
pub struct KeyPairGenerator {
    entry: &'static KeyPairGeneratorEntry,
    params: Option<KeyGenParams>,
    rng: Box<dyn CryptoRng + Send>,
}

impl KeyPairGenerator {
    pub fn entry(&self) -> &'static KeyPairGeneratorEntry {
        todo!()
    }

    pub fn with_rng(&mut self, rng: impl CryptoRng + Send + 'static) -> &mut Self {
        todo!()
    }

    pub fn init(&mut self, params: &KeyGenParams) -> Result<(), AlgoError> {
        todo!()
    }

    pub fn generate(&mut self) -> Result<KeyPair, AlgoError> {
        todo!()
    }
}

// Shows the generator's name, never its randomness
impl fmt::Debug for KeyPairGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}
