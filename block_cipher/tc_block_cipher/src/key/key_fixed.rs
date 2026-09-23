use tc_zeroize::{Zeroize, ZeroizeOnDrop};
use crate::KeyParams;

pub struct KeyFixed<const N: usize> {
    key: [u8; N],
}

impl<const N: usize> KeyFixed<N> {
    pub const fn new(key: [u8; N]) -> Self {
        Self { key }
    }
}

impl<const N: usize> KeyParams for KeyFixed<N> {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl<const N: usize> Zeroize for KeyFixed<N> {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<const N: usize> Drop for KeyFixed<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for KeyFixed<N> {}