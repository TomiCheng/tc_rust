use core::any::Any;

use crate::Params;

// What a DRBG is seeded again with, by Drbg::init: a nonce and a personalization string, both
// empty unless set. An empty nonce is drawn from the random source instead. Nothing is checked here
#[derive(Clone, Debug, Default)]
pub struct DrbgParams {
    nonce: Vec<u8>,
    personalization: Vec<u8>,
}

impl DrbgParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn with_personalization(mut self, personalization: Vec<u8>) -> Self {
        self.personalization = personalization;
        self
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn personalization(&self) -> &[u8] {
        &self.personalization
    }
}

impl Params for DrbgParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
