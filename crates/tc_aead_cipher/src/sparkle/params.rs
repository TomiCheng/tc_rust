//! SCHWAEMM initialization parameters.

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::Params;

/// Borrowed SCHWAEMM key, nonce, and optional initial AAD.
///
/// Exact key and nonce lengths depend on the selected [`super::Variant`] and
/// are checked by [`super::Engine::init`](tc_cipher_core::AeadCipherInit::init).
pub struct BorrowedParams<'a> {
    key: &'a [u8],
    nonce: &'a [u8],
    initial_aad: &'a [u8],
}

impl<'a> BorrowedParams<'a> {
    /// Borrows a key and nonce without initial AAD.
    pub const fn new(key: &'a [u8], nonce: &'a [u8]) -> Self {
        Self::new_with_aad(key, nonce, &[])
    }

    /// Borrows a key, nonce, and initial AAD.
    pub const fn new_with_aad(key: &'a [u8], nonce: &'a [u8], initial_aad: &'a [u8]) -> Self {
        Self {
            key,
            nonce,
            initial_aad,
        }
    }

    /// Returns the initial associated data supplied with these parameters.
    pub const fn initial_aad(&self) -> &[u8] {
        self.initial_aad
    }
}

impl Params for BorrowedParams<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }

    fn nonce(&self) -> &[u8] {
        self.nonce
    }

    fn initial_aad(&self) -> &[u8] {
        self.initial_aad
    }
}

impl fmt::Debug for BorrowedParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BorrowedParams")
            .field("key_len", &self.key.len())
            .field("nonce_len", &self.nonce.len())
            .field("initial_aad_len", &self.initial_aad.len())
            .finish()
    }
}

/// Owned SCHWAEMM key, nonce, and optional initial AAD.
///
/// This type is available with the `alloc` feature. Exact key and nonce
/// lengths are checked by the selected engine during initialization.
#[cfg(feature = "alloc")]
pub struct OwnedParams {
    key: Vec<u8>,
    nonce: Vec<u8>,
    initial_aad: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl OwnedParams {
    /// Copies a key and nonce without initial AAD.
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self::new_with_aad(key, nonce, Vec::new())
    }

    /// Copies a key and nonce, taking ownership of the initial AAD.
    pub fn new_with_aad(key: &[u8], nonce: &[u8], initial_aad: Vec<u8>) -> Self {
        Self {
            key: key.into(),
            nonce: nonce.into(),
            initial_aad,
        }
    }

    /// Returns the initial associated data supplied with these parameters.
    pub fn initial_aad(&self) -> &[u8] {
        &self.initial_aad
    }
}

#[cfg(feature = "alloc")]
impl Params for OwnedParams {
    fn key(&self) -> &[u8] {
        &self.key
    }

    fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    fn initial_aad(&self) -> &[u8] {
        &self.initial_aad
    }
}

#[cfg(feature = "alloc")]
impl fmt::Debug for OwnedParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedParams")
            .field("key_len", &self.key.len())
            .field("nonce_len", &self.nonce.len())
            .field("initial_aad_len", &self.initial_aad.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn borrowed_params_keep_all_inputs_borrowed() {
        let key = [0xA5; 16];
        let nonce = [0x5A; 32];
        let aad = [0x3C; 7];
        let params = BorrowedParams::new_with_aad(&key, &nonce, &aad);

        assert!(core::ptr::eq(params.key(), &key));
        assert!(core::ptr::eq(params.nonce(), &nonce));
        assert!(core::ptr::eq(params.initial_aad(), &aad));
    }

    #[test]
    fn borrowed_debug_redacts_material() {
        let params = BorrowedParams::new_with_aad(&[0xA5; 16], &[0x5A; 32], &[0x3C; 7]);

        assert_eq!(
            format!("{params:?}"),
            "BorrowedParams { key_len: 16, nonce_len: 32, initial_aad_len: 7 }"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_params_copy_key_and_nonce_and_take_aad() {
        let mut key = [0xA5; 24];
        let mut nonce = [0x5A; 24];
        let aad = std::vec![0x3C; 7];
        let aad_ptr = aad.as_ptr();
        let params = OwnedParams::new_with_aad(&key, &nonce, aad);

        key.fill(0);
        nonce.fill(0);

        assert_eq!(params.key(), &[0xA5; 24]);
        assert_eq!(params.nonce(), &[0x5A; 24]);
        assert_eq!(params.initial_aad(), &[0x3C; 7]);
        assert_eq!(params.initial_aad().as_ptr(), aad_ptr);
    }
}
