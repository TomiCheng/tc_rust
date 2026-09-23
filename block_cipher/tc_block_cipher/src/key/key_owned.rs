use alloc::vec::Vec;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};
use crate::KeyParams;

pub struct KeyOwned {
    key: Vec<u8>,
}

impl KeyOwned {
    pub const fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl KeyParams for KeyOwned {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Zeroize for KeyOwned {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for KeyOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyOwned {}