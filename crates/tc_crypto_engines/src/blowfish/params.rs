//! Blowfish initialization parameters.

use alloc::vec::Vec;
use core::fmt;

use super::{BLOWFISH_MAX_KEY_BYTES, BLOWFISH_MIN_KEY_BYTES, BlowfishError};

/// An owned Blowfish key containing between 4 and 56 bytes.
pub struct BlowfishParams {
    key: Vec<u8>,
}

impl BlowfishParams {
    /// Copies a Blowfish key containing between 4 and 56 bytes.
    pub fn new(key: &[u8]) -> Result<Self, BlowfishError> {
        if !(BLOWFISH_MIN_KEY_BYTES..=BLOWFISH_MAX_KEY_BYTES).contains(&key.len()) {
            return Err(BlowfishError::InvalidKeyLength(key.len()));
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

impl fmt::Debug for BlowfishParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlowfishParams")
            .field("key_len", &self.key_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_standard_key_length_range() {
        for length in [4, 5, 8, 16, 32, 55, 56] {
            assert_eq!(
                BlowfishParams::new(&alloc::vec![0u8; length])
                    .unwrap()
                    .key_len(),
                length
            );
        }
        for length in [0, 1, 3, 57, 59] {
            assert!(matches!(
                BlowfishParams::new(&alloc::vec![0u8; length]),
                Err(BlowfishError::InvalidKeyLength(n)) if n == length
            ));
        }
    }

    #[test]
    fn owns_and_redacts_key_material() {
        let params = {
            let key = [0xA5; 24];
            BlowfishParams::new(&key).unwrap()
        };
        assert_eq!(params.key(), &[0xA5; 24]);
        assert_eq!(
            alloc::format!("{params:?}"),
            "BlowfishParams { key_len: 24 }"
        );
    }
}
