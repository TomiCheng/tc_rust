//! Validated Noekeon initialization parameters.

use core::fmt;

use super::{NOEKEON_KEY_BYTES, BlockCipherError};

/// Owned, validated Noekeon key parameter (128 bits).
pub struct NoekeonParams {
    key: [u8; NOEKEON_KEY_BYTES],
}

impl fmt::Debug for NoekeonParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoekeonParams")
            .field("key_len", &NOEKEON_KEY_BYTES)
            .finish()
    }
}

impl NoekeonParams {
    /// Validates that `key` is exactly 16 bytes and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let key: &[u8; NOEKEON_KEY_BYTES] = key
            .try_into()
            .map_err(|_| BlockCipherError::InvalidKeyLength(key.len()))?;
        Ok(Self { key: *key })
    }

    pub(crate) const fn key(&self) -> &[u8; NOEKEON_KEY_BYTES] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            NoekeonParams::new(&[0u8; 15]),
            Err(BlockCipherError::InvalidKeyLength(15))
        ));
        assert!(matches!(
            NoekeonParams::new(&[0u8; 24]),
            Err(BlockCipherError::InvalidKeyLength(24))
        ));
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = NoekeonParams::new(&[0xA5u8; NOEKEON_KEY_BYTES]).unwrap();
        assert_eq!(
            alloc::format!("{params:?}"),
            "NoekeonParams { key_len: 16 }"
        );
    }
}
