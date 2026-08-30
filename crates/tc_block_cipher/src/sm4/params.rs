//! Validated SM4 initialization parameters.

use core::fmt;

use super::{SM4_KEY_BYTES, BlockCipherError};

/// Owned, validated SM4 key parameter (128 bits).
pub struct Sm4Params {
    key: [u8; SM4_KEY_BYTES],
}

impl fmt::Debug for Sm4Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sm4Params")
            .field("key_len", &SM4_KEY_BYTES)
            .finish()
    }
}

impl Sm4Params {
    /// Validates that `key` is exactly 16 bytes and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let key: &[u8; SM4_KEY_BYTES] = key
            .try_into()
            .map_err(|_| BlockCipherError::InvalidKeyLength(key.len()))?;
        Ok(Self { key: *key })
    }

    pub(crate) const fn key(&self) -> &[u8; SM4_KEY_BYTES] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            Sm4Params::new(&[0u8; 15]),
            Err(BlockCipherError::InvalidKeyLength(15))
        ));
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = Sm4Params::new(&[0xA5u8; SM4_KEY_BYTES]).unwrap();
        assert_eq!(format!("{params:?}"), "Sm4Params { key_len: 16 }");
    }
}
