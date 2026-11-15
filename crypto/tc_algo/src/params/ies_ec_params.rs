use core::any::Any;

use crate::Params;

// The params of the ECIES row, as IesDhParams for IES: this side's private key and the other side's
// public key, with what Bouncy Castle's IesParameters holds. The keys are as the EC key pair
// generator gives them, behind dyn Params, since each curve is a type of its own; the row finds the
// curve when it is initialized, and refuses keys on two curves
pub struct IesEcParams {
    private_key: Box<dyn Params>,
    public_key: Box<dyn Params>,
    derivation_v: Vec<u8>,
    encoding_v: Vec<u8>,
    mac_key_bits: usize,
}

impl IesEcParams {
    pub fn new(
        private_key: Box<dyn Params>,
        public_key: Box<dyn Params>,
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

    pub fn private_key(&self) -> &dyn Params {
        self.private_key.as_ref()
    }

    pub fn public_key(&self) -> &dyn Params {
        self.public_key.as_ref()
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

impl Params for IesEcParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
