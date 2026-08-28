//! Validated TEA initialization parameters.

use core::fmt;

use super::{TEA_KEY_BYTES, BlockCipherError};

/// Owned, validated TEA key parameter (128 bits).
pub struct TeaParams {
    key: [u8; TEA_KEY_BYTES],
}

impl fmt::Debug for TeaParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeaParams")
            .field("key_len", &TEA_KEY_BYTES)
            .finish()
    }
}

impl TeaParams {
    /// Validates that `key` is exactly 16 bytes and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let key: &[u8; TEA_KEY_BYTES] = key
            .try_into()
            .map_err(|_| BlockCipherError::InvalidKeyLength(key.len()))?;
        Ok(Self { key: *key })
    }

    pub(crate) const fn key(&self) -> &[u8; TEA_KEY_BYTES] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            TeaParams::new(&[0u8; 15]),
            Err(BlockCipherError::InvalidKeyLength(15))
        ));
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = TeaParams::new(&[0xA5u8; TEA_KEY_BYTES]).unwrap();
        assert_eq!(alloc::format!("{params:?}"), "TeaParams { key_len: 16 }");
    }
}
