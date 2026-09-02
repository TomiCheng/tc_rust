//! Key-with-IV parameter abstraction.

use core::fmt;

use crate::{IvParams, KeyParams};

/// Borrowed key and initialization-vector parameters.
///
/// This wrapper does not validate either value. The consuming algorithm owns
/// all key- and IV-length policy.
pub struct KeyWithIvRef<'a> {
    key: &'a [u8],
    iv: &'a [u8],
}

impl<'a> KeyWithIvRef<'a> {
    /// Borrows `key` and `iv` without copying or validating them.
    pub const fn new(key: &'a [u8], iv: &'a [u8]) -> Self {
        Self { key, iv }
    }
}

impl KeyParams for KeyWithIvRef<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for KeyWithIvRef<'_> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

impl fmt::Debug for KeyWithIvRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithIvRef")
            .field("key_len", &self.key.len())
            .field("iv_len", &self.iv.len())
            .finish()
    }
}

/// Owned, fixed-size key and initialization-vector parameters.
///
/// The array sizes are part of the type. This wrapper does not restrict them;
/// the consuming algorithm still validates both lengths when initialized.
pub struct KeyWithIvOwned<const K: usize, const I: usize> {
    key: [u8; K],
    iv: [u8; I],
}

impl<const K: usize, const I: usize> KeyWithIvOwned<K, I> {
    /// Takes ownership of `key` and `iv`.
    pub const fn new(key: [u8; K], iv: [u8; I]) -> Self {
        Self { key, iv }
    }
}

impl<const K: usize, const I: usize> KeyParams for KeyWithIvOwned<K, I> {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl<const K: usize, const I: usize> IvParams for KeyWithIvOwned<K, I> {
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl<const K: usize, const I: usize> fmt::Debug for KeyWithIvOwned<K, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWithIvOwned")
            .field("key_len", &K)
            .field("iv_len", &I)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::{IvParams, KeyParams, KeyWithIvOwned, KeyWithIvRef};

    struct KeyAndIv<'a> {
        key: &'a [u8],
        iv: &'a [u8],
    }

    impl KeyParams for KeyAndIv<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }

    impl IvParams for KeyAndIv<'_> {
        fn iv(&self) -> &[u8] {
            self.iv
        }
    }

    #[test]
    fn values_are_reachable_through_the_individual_traits() {
        let key = [0x01_u8, 0x02, 0x03];
        let iv = [0x04_u8, 0x05];
        let params = KeyAndIv { key: &key, iv: &iv };

        assert_eq!((&params as &dyn KeyParams).key(), &key);
        assert_eq!((&params as &dyn IvParams).iv(), &iv);
    }

    #[test]
    fn borrowed_values_are_reachable_through_a_trait_object() {
        let key = [0x01_u8, 0x02, 0x03];
        let iv = [0x04_u8, 0x05];
        let params = KeyWithIvRef::new(&key, &iv);

        assert_eq!((&params as &dyn KeyParams).key(), &key);
        assert_eq!((&params as &dyn IvParams).iv(), &iv);
    }

    #[test]
    fn owned_values_outlive_the_source_scope() {
        let params = {
            let key = [0x11_u8; 4];
            let iv = [0x22_u8; 2];
            KeyWithIvOwned::new(key, iv)
        };

        assert_eq!((&params as &dyn KeyParams).key(), &[0x11; 4]);
        assert_eq!((&params as &dyn IvParams).iv(), &[0x22; 2]);
    }

    #[test]
    fn debug_redacts_key_and_iv_material() {
        assert_eq!(
            format!("{:?}", KeyWithIvRef::new(&[0xff; 4], &[0xee; 2])),
            "KeyWithIvRef { key_len: 4, iv_len: 2 }"
        );
        assert_eq!(
            format!("{:?}", KeyWithIvOwned::new([0xff; 4], [0xee; 2])),
            "KeyWithIvOwned { key_len: 4, iv_len: 2 }"
        );
    }
}
