use rand_core::CryptoRng;

// What DefaultAlgoBuilder hands to the functions registered with it
pub struct DefaultAlgoContext {
    rand: fn() -> Box<dyn CryptoRng>,
}

impl DefaultAlgoContext {
    pub(crate) fn new(rand: fn() -> Box<dyn CryptoRng>) -> Self {
        Self { rand }
    }

    #[cfg_attr(not(feature = "aes"), allow(dead_code))]
    pub(crate) fn rand(&self) -> fn() -> Box<dyn CryptoRng> {
        self.rand
    }
}
