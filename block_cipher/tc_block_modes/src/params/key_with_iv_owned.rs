use alloc::vec::Vec;
use core::fmt;
use tc_block_cipher::KeyParams;
use tc_zeroize::{Zeroize, ZeroizeOnDrop};
use crate::IvParams;

/// Owned key and initialization-vector vectors, wiped on drop.
///
/// Construction transfers the vectors rather than cloning their bytes. The
/// consuming algorithm validates both lengths when initialized.
pub struct KeyWithIvOwned {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl KeyWithIvOwned {
    /// Takes ownership of `key` and `iv` without allocating.
    pub const fn new(key: Vec<u8>, iv: Vec<u8>) -> Self {
        Self { key, iv }
    }
}

impl KeyParams for KeyWithIvOwned {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl IvParams for KeyWithIvOwned {
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl fmt::Debug for KeyWithIvOwned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithIvOwned")
            .field("key_len", &self.key.len())
            .field("iv_len", &self.iv.len())
            .finish()
    }
}

impl Zeroize for KeyWithIvOwned {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Drop for KeyWithIvOwned {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyWithIvOwned {}
