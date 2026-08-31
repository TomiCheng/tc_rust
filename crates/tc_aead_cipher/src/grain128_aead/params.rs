//! Grain-128AEAD initialization parameters.

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::{KEY_BYTES, NONCE_BYTES, Params};
use crate::AeadCipherError;

/// Borrowed Grain-128AEAD key, nonce, and optional initial AAD.
pub struct BorrowedParams<'a> {
    key: &'a [u8; KEY_BYTES],
    nonce: &'a [u8; NONCE_BYTES],
    aad_len: usize,
    initial_aad: &'a [u8],
}

impl<'a> BorrowedParams<'a> {
    /// Validates and borrows a key and nonce for an operation without AAD.
    pub fn new(key: &'a [u8], nonce: &'a [u8]) -> Result<Self, AeadCipherError> {
        Self::new_with_aad_and_len(key, nonce, &[], 0)
    }

    /// Validates and borrows a key, nonce, and complete initial AAD.
    pub fn new_with_aad(
        key: &'a [u8],
        nonce: &'a [u8],
        initial_aad: &'a [u8],
    ) -> Result<Self, AeadCipherError> {
        Self::new_with_aad_and_len(key, nonce, initial_aad, initial_aad.len())
    }

    /// Validates and borrows a key and nonce, declaring the total AAD length
    /// for subsequent incremental AAD calls.
    pub fn new_with_aad_len(
        key: &'a [u8],
        nonce: &'a [u8],
        aad_len: usize,
    ) -> Result<Self, AeadCipherError> {
        Self::new_with_aad_and_len(key, nonce, &[], aad_len)
    }

    /// Validates and borrows a key, nonce, and initial part of the declared
    /// AAD.
    pub fn new_with_aad_and_len(
        key: &'a [u8],
        nonce: &'a [u8],
        initial_aad: &'a [u8],
        aad_len: usize,
    ) -> Result<Self, AeadCipherError> {
        let key = key
            .try_into()
            .map_err(|_| AeadCipherError::InvalidKeyLength(key.len()))?;
        let nonce = nonce
            .try_into()
            .map_err(|_| AeadCipherError::InvalidNonceLength {
                expected: NONCE_BYTES,
                actual: nonce.len(),
            })?;
        if initial_aad.len() > aad_len {
            return Err(AeadCipherError::AadLengthMismatch {
                expected: aad_len,
                actual: initial_aad.len(),
            });
        }

        Ok(Self {
            key,
            nonce,
            aad_len,
            initial_aad,
        })
    }

    /// Returns the initial AAD supplied with these parameters.
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

    fn aad_len(&self) -> usize {
        self.aad_len
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
            .field("aad_len", &self.aad_len)
            .field("initial_aad_len", &self.initial_aad.len())
            .finish()
    }
}

/// Owned Grain-128AEAD key, nonce, and optional initial AAD.
#[cfg(feature = "alloc")]
pub struct OwnedParams {
    key: [u8; KEY_BYTES],
    nonce: [u8; NONCE_BYTES],
    aad_len: usize,
    initial_aad: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl OwnedParams {
    /// Validates and copies a key and nonce for an operation without AAD.
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, AeadCipherError> {
        Self::new_with_aad_and_len(key, nonce, Vec::new(), 0)
    }

    /// Validates and copies a key and nonce, taking the complete initial AAD.
    pub fn new_with_aad(
        key: &[u8],
        nonce: &[u8],
        initial_aad: Vec<u8>,
    ) -> Result<Self, AeadCipherError> {
        let aad_len = initial_aad.len();
        Self::new_with_aad_and_len(key, nonce, initial_aad, aad_len)
    }

    /// Validates and copies a key and nonce, declaring the total AAD length
    /// for subsequent incremental AAD calls.
    pub fn new_with_aad_len(
        key: &[u8],
        nonce: &[u8],
        aad_len: usize,
    ) -> Result<Self, AeadCipherError> {
        Self::new_with_aad_and_len(key, nonce, Vec::new(), aad_len)
    }

    /// Validates and copies a key and nonce, taking an initial part of the
    /// declared AAD.
    pub fn new_with_aad_and_len(
        key: &[u8],
        nonce: &[u8],
        initial_aad: Vec<u8>,
        aad_len: usize,
    ) -> Result<Self, AeadCipherError> {
        let key = key
            .try_into()
            .map_err(|_| AeadCipherError::InvalidKeyLength(key.len()))?;
        let nonce = nonce
            .try_into()
            .map_err(|_| AeadCipherError::InvalidNonceLength {
                expected: NONCE_BYTES,
                actual: nonce.len(),
            })?;
        if initial_aad.len() > aad_len {
            return Err(AeadCipherError::AadLengthMismatch {
                expected: aad_len,
                actual: initial_aad.len(),
            });
        }

        Ok(Self {
            key,
            nonce,
            aad_len,
            initial_aad,
        })
    }

    /// Returns the initial AAD supplied with these parameters.
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

    fn aad_len(&self) -> usize {
        self.aad_len
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
            .field("aad_len", &self.aad_len)
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
    fn borrowed_params_validate_lengths_and_aad_bounds() {
        let key = [0xA5; KEY_BYTES];
        let nonce = [0x5A; NONCE_BYTES];
        let aad = [0x3C; 7];
        let params = BorrowedParams::new_with_aad_and_len(&key, &nonce, &aad, 9).unwrap();

        assert!(core::ptr::eq(params.key(), &key));
        assert!(core::ptr::eq(params.nonce(), &nonce));
        assert!(core::ptr::eq(params.initial_aad(), &aad));
        assert_eq!(params.aad_len(), 9);

        assert!(matches!(
            BorrowedParams::new(&key[..KEY_BYTES - 1], &nonce),
            Err(AeadCipherError::InvalidKeyLength(actual)) if actual == KEY_BYTES - 1
        ));
        assert!(matches!(
            BorrowedParams::new(&key, &nonce[..NONCE_BYTES - 1]),
            Err(AeadCipherError::InvalidNonceLength {
                expected: NONCE_BYTES,
                actual,
            }) if actual == NONCE_BYTES - 1
        ));
        assert!(matches!(
            BorrowedParams::new_with_aad_and_len(&key, &nonce, &aad, 6),
            Err(AeadCipherError::AadLengthMismatch {
                expected: 6,
                actual: 7,
            })
        ));
    }

    #[test]
    fn borrowed_debug_redacts_material() {
        let params = BorrowedParams::new_with_aad(&[0xA5; 16], &[0x5A; 12], &[0x3C; 7]).unwrap();
        assert_eq!(
            format!("{params:?}"),
            "BorrowedParams { key_len: 16, nonce_len: 12, aad_len: 7, initial_aad_len: 7 }"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_params_copy_key_and_nonce_and_take_aad() {
        let mut key = [0xA5; KEY_BYTES];
        let mut nonce = [0x5A; NONCE_BYTES];
        let aad = std::vec![0x3C; 7];
        let aad_ptr = aad.as_ptr();
        let params = OwnedParams::new_with_aad(&key, &nonce, aad).unwrap();

        key.fill(0);
        nonce.fill(0);
        assert_eq!(params.key(), &[0xA5; KEY_BYTES]);
        assert_eq!(params.nonce(), &[0x5A; NONCE_BYTES]);
        assert_eq!(params.initial_aad(), &[0x3C; 7]);
        assert_eq!(params.initial_aad().as_ptr(), aad_ptr);
    }
}
