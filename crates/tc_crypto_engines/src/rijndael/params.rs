//! Validated Rijndael initialization parameters.

use alloc::vec::Vec;
use core::fmt;

use super::{RIJNDAEL_KEY_BYTES, BlockCipherError};

/// Owned, validated Rijndael key parameter (16/20/24/28/32 bytes).
pub struct RijndaelParams {
    key: Vec<u8>,
}

impl fmt::Debug for RijndaelParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RijndaelParams")
            .field("key_len", &self.key.len())
            .finish()
    }
}

impl RijndaelParams {
    /// Validates that `key` is a legal Rijndael key length and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        if !RIJNDAEL_KEY_BYTES.contains(&key.len()) {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }
        Ok(Self { key: key.to_vec() })
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            RijndaelParams::new(&[0u8; 17]),
            Err(BlockCipherError::InvalidKeyLength(17))
        ));
    }

    #[test]
    fn accepts_all_legal_lengths() {
        for len in RIJNDAEL_KEY_BYTES {
            assert!(RijndaelParams::new(&alloc::vec![0u8; len]).is_ok());
        }
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = RijndaelParams::new(&[0xA5u8; 24]).unwrap();
        assert_eq!(
            alloc::format!("{params:?}"),
            "RijndaelParams { key_len: 24 }"
        );
    }
}
