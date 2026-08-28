//! DSTU 7624 initialization parameters.

use alloc::vec::Vec;
use core::fmt;

use super::{DSTU7624_KEY_BYTES, BlockCipherError};

/// An owned DSTU 7624 key containing 16, 32, or 64 bytes.
pub struct Dstu7624Params {
    key: Vec<u8>,
}

impl Dstu7624Params {
    /// Copies and validates a DSTU 7624 key.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        if !DSTU7624_KEY_BYTES.contains(&key.len()) {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }
        Ok(Self { key: key.to_vec() })
    }

    /// Returns the key length in bytes without exposing key material.
    pub fn key_len(&self) -> usize {
        self.key.len()
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }
}

impl fmt::Debug for Dstu7624Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dstu7624Params")
            .field("key_len", &self.key_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_standard_key_lengths() {
        for length in DSTU7624_KEY_BYTES {
            assert_eq!(
                Dstu7624Params::new(&alloc::vec![0u8; length])
                    .unwrap()
                    .key_len(),
                length
            );
        }
        for length in [0, 15, 17, 31, 33, 63, 65] {
            assert!(matches!(
                Dstu7624Params::new(&alloc::vec![0u8; length]),
                Err(BlockCipherError::InvalidKeyLength(n)) if n == length
            ));
        }
    }

    #[test]
    fn owns_and_redacts_key_material() {
        let params = {
            let key = [0xA5; 32];
            Dstu7624Params::new(&key).unwrap()
        };
        assert_eq!(params.key(), &[0xA5; 32]);
        assert_eq!(
            alloc::format!("{params:?}"),
            "Dstu7624Params { key_len: 32 }"
        );
    }
}
