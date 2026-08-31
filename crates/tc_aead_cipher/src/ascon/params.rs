//! Validated legacy Ascon initialization parameters.

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::{KEY_BYTES_80PQ, KEY_BYTES_128, NONCE_BYTES, Params};
use crate::AeadCipherError;

/// Borrowed legacy Ascon key, nonce, and optional initial AAD.
pub struct BorrowedParams<'a> {
    key: &'a [u8],
    nonce: &'a [u8; NONCE_BYTES],
    initial_aad: &'a [u8],
}

impl<'a> BorrowedParams<'a> {
    /// Validates and borrows a supported key and 16-byte nonce without AAD.
    pub fn new(key: &'a [u8], nonce: &'a [u8]) -> Result<Self, AeadCipherError> {
        Self::new_with_aad(key, nonce, &[])
    }

    /// Validates and borrows a supported key, 16-byte nonce, and initial AAD.
    pub fn new_with_aad(
        key: &'a [u8],
        nonce: &'a [u8],
        initial_aad: &'a [u8],
    ) -> Result<Self, AeadCipherError> {
        validate_key_length(key.len())?;
        let nonce = nonce
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
    fn key(&self) -> &[u8] {
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

#[cfg(feature = "alloc")]
enum OwnedKey {
    Key128([u8; KEY_BYTES_128]),
    Key80pq([u8; KEY_BYTES_80PQ]),
}

#[cfg(feature = "alloc")]
impl OwnedKey {
    fn new(key: &[u8]) -> Result<Self, AeadCipherError> {
        match key.len() {
            KEY_BYTES_128 => Ok(Self::Key128(key.try_into().unwrap())),
            KEY_BYTES_80PQ => Ok(Self::Key80pq(key.try_into().unwrap())),
            actual => Err(AeadCipherError::InvalidKeyLength(actual)),
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Key128(key) => key,
            Self::Key80pq(key) => key,
        }
    }
}

/// Owned legacy Ascon key, nonce, and optional initial AAD.
#[cfg(feature = "alloc")]
pub struct OwnedParams {
    key: OwnedKey,
    nonce: [u8; NONCE_BYTES],
    initial_aad: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl OwnedParams {
    /// Validates and copies a supported key and 16-byte nonce without AAD.
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, AeadCipherError> {
        Self::new_with_aad(key, nonce, Vec::new())
    }

    /// Validates and copies a supported key and 16-byte nonce, taking
    /// ownership of the initial AAD.
    pub fn new_with_aad(
        key: &[u8],
        nonce: &[u8],
        initial_aad: Vec<u8>,
    ) -> Result<Self, AeadCipherError> {
        let key = OwnedKey::new(key)?;
        let nonce = nonce
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
    fn key(&self) -> &[u8] {
        self.key.as_slice()
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
            .field("key_len", &self.key.as_slice().len())
            .field("nonce_len", &self.nonce.len())
            .field("initial_aad_len", &self.initial_aad.len())
            .finish()
    }
}

fn validate_key_length(length: usize) -> Result<(), AeadCipherError> {
    match length {
        KEY_BYTES_128 | KEY_BYTES_80PQ => Ok(()),
        actual => Err(AeadCipherError::InvalidKeyLength(actual)),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn borrowed_params_accept_both_key_lengths() {
        for key_len in [KEY_BYTES_128, KEY_BYTES_80PQ] {
            let key = [0xA5; KEY_BYTES_80PQ];
            let nonce = [0x5A; NONCE_BYTES];
            let params = BorrowedParams::new(&key[..key_len], &nonce).unwrap();

            assert_eq!(params.key().len(), key_len);
            assert!(core::ptr::eq(params.nonce(), &nonce));
        }
    }

    #[test]
    fn borrowed_params_reject_invalid_lengths() {
        let key = [0_u8; KEY_BYTES_80PQ + 1];
        for key_len in [0, KEY_BYTES_128 - 1, KEY_BYTES_128 + 1, KEY_BYTES_80PQ + 1] {
            assert!(matches!(
                BorrowedParams::new(&key[..key_len], &[0_u8; NONCE_BYTES]),
                Err(AeadCipherError::InvalidKeyLength(actual)) if actual == key_len
            ));
        }

        assert!(matches!(
            BorrowedParams::new(&[0_u8; KEY_BYTES_128], &[0_u8; NONCE_BYTES - 1]),
            Err(AeadCipherError::InvalidNonceLength {
                expected: NONCE_BYTES,
                actual,
            }) if actual == NONCE_BYTES - 1
        ));
    }

    #[test]
    fn borrowed_debug_redacts_material() {
        let key = [0xA5; KEY_BYTES_80PQ];
        let nonce = [0x5A; NONCE_BYTES];
        let aad = [0x3C; 7];
        let params = BorrowedParams::new_with_aad(&key, &nonce, &aad).unwrap();

        assert_eq!(
            format!("{params:?}"),
            "BorrowedParams { key_len: 20, nonce_len: 16, initial_aad_len: 7 }"
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_params_copy_key_and_nonce_and_take_aad() {
        let mut key = [0xA5; KEY_BYTES_80PQ];
        let mut nonce = [0x5A; NONCE_BYTES];
        let aad = std::vec![0x3C; 7];
        let aad_ptr = aad.as_ptr();
        let params = OwnedParams::new_with_aad(&key, &nonce, aad).unwrap();

        key.fill(0);
        nonce.fill(0);

        assert_eq!(params.key(), &[0xA5; KEY_BYTES_80PQ]);
        assert_eq!(params.nonce(), &[0x5A; NONCE_BYTES]);
        assert_eq!(params.initial_aad(), &[0x3C; 7]);
        assert_eq!(params.initial_aad().as_ptr(), aad_ptr);
    }
}
