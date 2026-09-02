//! Key parameter abstraction.

use core::fmt;

/// Parameters that provide cryptographic key material.
pub trait KeyParams {
    /// Returns the key bytes.
    fn key(&self) -> &[u8];
}

/// A [`KeyParams`] implementation that borrows the key from the caller.
///
/// Algorithms validate the key length themselves, so this wrapper imposes no
/// policy of its own; it exists so that callers with key bytes already in hand
/// do not have to declare a type just to satisfy the trait.
///
/// ```
/// use tc_params::{KeyParams, KeyRef};
///
/// let key = [0x00, 0x11, 0x22, 0x33];
/// let params = KeyRef::new(&key);
/// assert_eq!(params.key(), &key);
/// ```
pub struct KeyRef<'a> {
    key: &'a [u8],
}

impl<'a> KeyRef<'a> {
    /// Wraps `key` without copying or validating it.
    pub const fn new(key: &'a [u8]) -> Self {
        Self { key }
    }
}

impl KeyParams for KeyRef<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl fmt::Debug for KeyRef<'_> {
    /// Reports the key length only, so that key material never reaches logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRef")
            .field("key_len", &self.key.len())
            .finish()
    }
}

/// A [`KeyParams`] implementation that owns a fixed-size key.
///
/// Use this where [`KeyRef`] cannot borrow for long enough: the key is copied
/// in, so the parameters outlive the buffer they were built from.
///
/// `N` fixes the length at the type level, so the array a value is built from
/// cannot be the wrong size. It does not tie the key to any one algorithm:
/// engines see only `dyn KeyParams`, so they still reject a length they do not
/// accept when they are initialized.
///
/// ```
/// use tc_params::{KeyOwned, KeyParams};
///
/// let params = {
///     let key = [0xa5_u8; 16];
///     KeyOwned::new(key)
/// };
/// assert_eq!(params.key(), &[0xa5; 16]);
/// ```
pub struct KeyOwned<const N: usize> {
    key: [u8; N],
}

impl<const N: usize> KeyOwned<N> {
    /// Takes ownership of `key`.
    pub const fn new(key: [u8; N]) -> Self {
        Self { key }
    }
}

impl<const N: usize> KeyParams for KeyOwned<N> {
    fn key(&self) -> &[u8] {
        &self.key
    }
}

impl<const N: usize> fmt::Debug for KeyOwned<N> {
    /// Reports the key length only, so that key material never reaches logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyOwned").field("key_len", &N).finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::{KeyOwned, KeyParams, KeyRef};

    #[test]
    fn borrows_the_key_without_validating_it() {
        let key = [0xa5_u8; 8];
        assert_eq!(KeyRef::new(&key).key(), &key);
        // 長度政策屬於各演算法,包裝本身連空金鑰都照收。
        assert_eq!(KeyRef::new(&[]).key(), &[] as &[u8]);
    }

    #[test]
    fn is_usable_through_the_trait_object() {
        let key = [0x01_u8, 0x02, 0x03];
        let params = KeyRef::new(&key);
        let params: &dyn KeyParams = &params;
        assert_eq!(params.key(), &key);
    }

    #[test]
    fn debug_redacts_the_key() {
        let params = KeyRef::new(&[0xff_u8; 16]);
        assert_eq!(format!("{params:?}"), "KeyRef { key_len: 16 }");
    }

    #[test]
    fn owned_keys_outlive_the_buffer_they_came_from() {
        let params = {
            let key = [0x11_u8; 4];
            KeyOwned::new(key)
        };
        assert_eq!(params.key(), &[0x11; 4]);
    }

    #[test]
    fn owned_keys_are_usable_through_the_trait_object() {
        let params = KeyOwned::new([0x01_u8, 0x02, 0x03]);
        let params: &dyn KeyParams = &params;
        assert_eq!(params.key(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn owned_debug_redacts_the_key() {
        let params = KeyOwned::new([0xff_u8; 16]);
        assert_eq!(format!("{params:?}"), "KeyOwned { key_len: 16 }");
    }
}
