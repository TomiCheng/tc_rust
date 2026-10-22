use rand_core::CryptoRng;

pub struct KeyGenerationParams<'a> {
    pub(crate) rng: &'a mut dyn CryptoRng,
}

impl<'a> KeyGenerationParams<'a> {
    pub fn new(rng: &'a mut dyn CryptoRng) -> Self {
        Self { rng }
    }
}
