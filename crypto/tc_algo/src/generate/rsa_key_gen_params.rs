// Bouncy Castle's RsaKeyGenerationParameters. KeyGenParams::rsa() starts it at Bouncy Castle's
// defaults and the with_ methods change one value each; the fields stay public, as plain data
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RsaKeyGenParams {
    pub public_exponent: u32,
    pub bits: usize,
    pub certainty: u32,
}

impl RsaKeyGenParams {
    pub(super) const DEFAULT: Self = Self {
        public_exponent: 65537,
        bits: 2048,
        certainty: 100,
    };

    pub fn with_public_exponent(mut self, public_exponent: u32) -> Self {
        self.public_exponent = public_exponent;
        self
    }

    pub fn with_bits(mut self, bits: usize) -> Self {
        self.bits = bits;
        self
    }

    pub fn with_certainty(mut self, certainty: u32) -> Self {
        self.certainty = certainty;
        self
    }
}

impl From<RsaKeyGenParams> for super::KeyGenParams {
    fn from(params: RsaKeyGenParams) -> Self {
        Self::Rsa(params)
    }
}
