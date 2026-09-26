use core::fmt;
use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};
use crate::IvParams;

/// Owned, fixed-size key and initialization-vector parameters, wiped on drop.
///
/// The array sizes are part of the type. This wrapper does not restrict them;
/// the consuming algorithm still validates both lengths when initialized.
pub struct KeyWithIvFixed<const K: usize, const I: usize> {
    key: [u8; K],
    iv: [u8; I],
}

impl<const K: usize, const I: usize> KeyWithIvFixed<K, I> {
    /// Takes ownership of `key` and `iv`.
    pub const fn new(key: [u8; K], iv: [u8; I]) -> Self {
        Self { key, iv }
    }
}

impl<const K: usize, const I: usize> KeyParams for KeyWithIvFixed<K, I> {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl<const K: usize, const I: usize> IvParams for KeyWithIvFixed<K, I> {
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl<const K: usize, const I: usize> fmt::Debug for KeyWithIvFixed<K, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithIvFixed")
            .field("key_len", &K)
            .field("iv_len", &I)
            .finish()
    }
}

impl<const K: usize, const I: usize> Zeroize for KeyWithIvFixed<K, I> {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl<const K: usize, const I: usize> Drop for KeyWithIvFixed<K, I> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const K: usize, const I: usize> ZeroizeOnDrop for KeyWithIvFixed<K, I> {}
