//! Validated Ascon-AEAD128 initialization parameters.

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::{KEY_BYTES, NONCE_BYTES, Params};
use crate::AeadCipherError;

/// Validated Ascon-AEAD128 key, nonce, and optional initial AAD.
///
/// All three inputs are borrowed so the parameters remain `no_std` without
/// requiring `alloc` or copying secret material. Ascon-AEAD128 has a fixed
/// 16-byte authentication tag.
pub struct BorrowedParams<'a> {
    pub(super) key: &'a [u8; KEY_BYTES],
    pub(super) nonce: &'a [u8; NONCE_BYTES],
    pub(super) initial_aad: &'a [u8],
}

impl<'a> BorrowedParams<'a> {
    /// Validates and borrows a 16-byte key and nonce without initial AAD.
    ///
    /// This corresponds to Bouncy Castle's `ParametersWithIV` initialization
    /// path.
    pub fn new(key: &'a [u8], nonce: &'a [u8]) -> Result<Self, AeadCipherError> {
        Self::new_with_aad(key, nonce, &[])
    }

    /// Validates and borrows a 16-byte key, nonce, and initial AAD.
    ///
    /// This corresponds to the information accepted through Bouncy Castle's
    /// `AeadParameters`. The tag size is omitted because Ascon-AEAD128 only
    /// accepts a 128-bit tag.
    pub fn new_with_aad(
        key: &'a [u8],
        nonce: &'a [u8],
        initial_aad: &'a [u8],
    ) -> Result<Self, AeadCipherError> {
        let key: &[u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| AeadCipherError::InvalidKeyLength(key.len()))?;
        let nonce: &[u8; NONCE_BYTES] =
            nonce
                .try_into()
                .map_err(|_| AeadCipherError::InvalidNonceLength {
                    expected: NONCE_BYTES,
                    actual: nonce.len(),
                })?;

        Ok(Self {
            key,
            nonce,
            initial_aad,
        })
    }

    /// Returns the initial associated data supplied with these parameters.
    pub const fn initial_aad(&self) -> &[u8] {
        self.initial_aad
    }
}

impl Params for BorrowedParams<'_> {
    fn key(&self) -> &[u8; KEY_BYTES] {
        self.key
    }

    fn nonce(&self) -> &[u8; NONCE_BYTES] {
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

/// Owned Ascon-AEAD128 key, nonce, and optional initial AAD.
///
/// This type is available with the `alloc` feature. Key and nonce bytes are
/// copied into fixed-size arrays, while the variable-length initial AAD is
/// stored in a [`Vec`].
#[cfg(feature = "alloc")]
pub struct OwnedParams {
    key: [u8; KEY_BYTES],
    nonce: [u8; NONCE_BYTES],
    initial_aad: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl OwnedParams {
    /// Validates and copies a 16-byte key and nonce without initial AAD.
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, AeadCipherError> {
        Self::new_with_aad(key, nonce, Vec::new())
    }

    /// Validates and copies a 16-byte key and nonce, taking ownership of the
    /// initial AAD.
    pub fn new_with_aad(
        key: &[u8],
        nonce: &[u8],
        initial_aad: Vec<u8>,
    ) -> Result<Self, AeadCipherError> {
        let key: [u8; KEY_BYTES] = key
            .try_into()
            .map_err(|_| AeadCipherError::InvalidKeyLength(key.len()))?;
        let nonce: [u8; NONCE_BYTES] =
            nonce
                .try_into()
                .map_err(|_| AeadCipherError::InvalidNonceLength {
                    expected: NONCE_BYTES,
                    actual: nonce.len(),
                })?;

        Ok(Self {
            key,
            nonce,
            initial_aad,
        })
    }

    /// Returns the initial associated data supplied with these parameters.
    pub fn initial_aad(&self) -> &[u8] {
        &self.initial_aad
    }
}

#[cfg(feature = "alloc")]
impl Params for OwnedParams {
    fn key(&self) -> &[u8; KEY_BYTES] {
        &self.key
    }

    fn nonce(&self) -> &[u8; NONCE_BYTES] {
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
    fn borrows_fixed_length_key_and_nonce() {
        let key = [0xA5; KEY_BYTES];
        let nonce = [0x5A; NONCE_BYTES];
        let params = BorrowedParams::new(&key, &nonce).unwrap();

        assert!(core::ptr::eq(params.key, &key));
        assert!(core::ptr::eq(params.nonce, &nonce));
        assert!(params.initial_aad().is_empty());
    }

    #[test]
    fn borrows_initial_aad() {
        let key = [0u8; KEY_BYTES];
        let nonce = [0u8; NONCE_BYTES];
        let initial_aad = [0x3C; 7];
        let params = BorrowedParams::new_with_aad(&key, &nonce, &initial_aad).unwrap();

        assert_eq!(params.initial_aad(), &initial_aad);
        assert_eq!(params.initial_aad().as_ptr(), initial_aad.as_ptr());
    }

    #[test]
    fn rejects_invalid_key_lengths() {
        for length in [0, 15, 17] {
            let key = [0u8; 17];
            assert!(matches!(
                BorrowedParams::new(
                    &key[..length],
                    &[0u8; NONCE_BYTES]
                ),
                Err(AeadCipherError::InvalidKeyLength(actual)) if actual == length
            ));
        }
    }

    #[test]
    fn rejects_invalid_nonce_lengths() {
        for length in [0, 15, 17] {
            let nonce = [0u8; 17];
            assert!(matches!(
                BorrowedParams::new(
                    &[0u8; KEY_BYTES],
                    &nonce[..length]
                ),
                Err(AeadCipherError::InvalidNonceLength {
                    expected: NONCE_BYTES,
                    actual,
                }) if actual == length
            ));
        }
    }

    #[test]
    fn debug_redacts_key_and_nonce_material() {
        let key = [0xA5; KEY_BYTES];
        let nonce = [0x5A; NONCE_BYTES];
        let params = BorrowedParams::new(&key, &nonce).unwrap();

        assert_eq!(
            format!("{params:?}"),
            "BorrowedParams { key_len: 16, nonce_len: 16, initial_aad_len: 0 }"
        );

        let initial_aad = [0x3C; 7];
        let params = BorrowedParams::new_with_aad(&key, &nonce, &initial_aad).unwrap();
        assert_eq!(
            format!("{params:?}"),
            "BorrowedParams { key_len: 16, nonce_len: 16, initial_aad_len: 7 }"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owns_key_nonce_and_initial_aad() {
        let mut key = [0xA5; KEY_BYTES];
        let mut nonce = [0x5A; NONCE_BYTES];
        let initial_aad = std::vec![0x3C; 7];
        let initial_aad_ptr = initial_aad.as_ptr();
        let params = OwnedParams::new_with_aad(&key, &nonce, initial_aad).unwrap();

        key.fill(0);
        nonce.fill(0);

        assert_eq!(params.key(), &[0xA5; KEY_BYTES]);
        assert_eq!(params.nonce(), &[0x5A; NONCE_BYTES]);
        assert_eq!(params.initial_aad(), &[0x3C; 7]);
        assert_eq!(params.initial_aad().as_ptr(), initial_aad_ptr);
        assert_eq!(
            format!("{params:?}"),
            "OwnedParams { key_len: 16, nonce_len: 16, initial_aad_len: 7 }"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_params_reject_invalid_lengths() {
        assert!(matches!(
            OwnedParams::new(&[0_u8; KEY_BYTES - 1], &[0_u8; NONCE_BYTES]),
            Err(AeadCipherError::InvalidKeyLength(actual)) if actual == KEY_BYTES - 1
        ));
        assert!(matches!(
            OwnedParams::new(&[0_u8; KEY_BYTES], &[0_u8; NONCE_BYTES + 1]),
            Err(AeadCipherError::InvalidNonceLength {
                expected: NONCE_BYTES,
                actual,
            }) if actual == NONCE_BYTES + 1
        ));
    }
}
