use rand::rngs::SysRng;
use rand_core::{CryptoRng, UnwrapErr};

// What DefaultAlgoBuilder hands to the functions registered with it
pub struct DefaultAlgoContext {
    rand: fn() -> Box<dyn CryptoRng>,
}

impl DefaultAlgoContext {
    pub(crate) fn new(rand: fn() -> Box<dyn CryptoRng>) -> Self {
        Self { rand }
    }

    #[cfg_attr(not(any(feature = "aes", feature = "chacha", feature = "hmac-sha256")), allow(dead_code))]
    pub(crate) fn rand(&self) -> fn() -> Box<dyn CryptoRng> {
        self.rand
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self::new(os_rand)
    }
}

// The operating system's random numbers; a failure to get them panics
pub(crate) fn os_rand() -> Box<dyn CryptoRng> {
    Box::new(UnwrapErr(SysRng))
}
