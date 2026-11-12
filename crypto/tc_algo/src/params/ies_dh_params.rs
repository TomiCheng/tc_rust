use core::any::Any;

use tc_dh_key::{DhPrivateKey, DhPublicKey};

use crate::Params;

// The params of the IES row: this side's private key and the other side's public key, with what
// Bouncy Castle's IesParameters holds. Its BufferedIesCipher has no Init yet, so there the four go
// to IesEngine.Init instead
pub struct IesDhParams {
    private_key: DhPrivateKey,
    public_key: DhPublicKey,
    derivation_v: Vec<u8>,
    encoding_v: Vec<u8>,
    mac_key_bits: usize,
}

impl IesDhParams {
    pub fn new(
        private_key: DhPrivateKey,
        public_key: DhPublicKey,
        derivation_v: Vec<u8>,
        encoding_v: Vec<u8>,
        mac_key_bits: usize,
    ) -> Self {
        Self {
            private_key,
            public_key,
            derivation_v,
            encoding_v,
            mac_key_bits,
        }
    }

    pub fn private_key(&self) -> &DhPrivateKey {
        &self.private_key
    }

    pub fn public_key(&self) -> &DhPublicKey {
        &self.public_key
    }

    pub fn derivation_v(&self) -> &[u8] {
        &self.derivation_v
    }

    pub fn encoding_v(&self) -> &[u8] {
        &self.encoding_v
    }

    pub fn mac_key_bits(&self) -> usize {
        self.mac_key_bits
    }
}

impl Params for IesDhParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
