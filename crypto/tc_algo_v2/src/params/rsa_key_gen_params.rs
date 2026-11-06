use core::any::Any;

use crate::Params;

// What an RSA key pair is generated to: Bouncy Castle's RsaKeyGenerationParameters without its random
// source, since the keys draw from DefaultAlgoBuilder::set_rand. The strength has no default, and the
// rest start at those of Bouncy Castle. Nothing is checked here: tc_rsa judges them at init
#[derive(Clone, Copy, Debug)]
pub struct RsaKeyGenParams {
    strength: u32,
    public_exponent: u32,
    certainty: u32,
}

impl RsaKeyGenParams {
    // A modulus of `strength` bits, the public exponent 65537, and primes tested to the certainty 100
    pub fn new(strength: u32) -> Self {
        Self {
            strength,
            public_exponent: 65537,
            certainty: 100,
        }
    }

    pub fn with_public_exponent(mut self, public_exponent: u32) -> Self {
        self.public_exponent = public_exponent;
        self
    }

    pub fn with_certainty(mut self, certainty: u32) -> Self {
        self.certainty = certainty;
        self
    }

    pub fn strength(&self) -> u32 {
        self.strength
    }

    pub fn public_exponent(&self) -> u32 {
        self.public_exponent
    }

    pub fn certainty(&self) -> u32 {
        self.certainty
    }
}

impl Params for RsaKeyGenParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
