use core::any::Any;

use crate::Params;

// How many bytes of key to generate; whether that many will do is for KeyGenerator::init to judge
pub struct KeyLength(usize);

impl KeyLength {
    pub fn new(bytes: usize) -> Self {
        Self(bytes)
    }

    pub fn bytes(&self) -> usize {
        self.0
    }
}

impl Params for KeyLength {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
