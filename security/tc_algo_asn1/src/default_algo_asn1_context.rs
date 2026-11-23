use rand::rngs::SysRng;
use rand_core::{CryptoRng, UnwrapErr};

// What DefaultAlgoAsn1Builder hands to the functions registered with it
pub struct DefaultAlgoAsn1Context {
    rand: fn() -> Box<dyn CryptoRng>,
}

impl DefaultAlgoAsn1Context {
    pub(crate) fn new(rand: fn() -> Box<dyn CryptoRng>) -> Self {
        Self { rand }
    }

    // What DefaultAlgoAsn1Builder::set_rand was given, for a row to keep and call when it needs
    // random numbers, as a cipher does for its IV
    pub fn rand(&self) -> fn() -> Box<dyn CryptoRng> {
        self.rand
    }
}

// The operating system's random numbers; a failure to get them panics
pub(crate) fn os_rand() -> Box<dyn CryptoRng> {
    Box::new(UnwrapErr(SysRng))
}
