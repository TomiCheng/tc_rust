//! Validated XTEA initialization parameters.

use core::fmt;

use super::{XTEA_KEY_BYTES, XteaError};

/// Owned, validated XTEA key parameter (128 bits).
pub struct XteaParams {
    key: [u8; XTEA_KEY_BYTES],
}

impl fmt::Debug for XteaParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XteaParams")
            .field("key_len", &XTEA_KEY_BYTES)
            .finish()
    }
}

impl XteaParams {
    /// Validates that `key` is exactly 16 bytes and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, XteaError> {
        let key: &[u8; XTEA_KEY_BYTES] = key
            .try_into()
            .map_err(|_| XteaError::InvalidKeyLength(key.len()))?;
        Ok(Self { key: *key })
    }

    pub(crate) const fn key(&self) -> &[u8; XTEA_KEY_BYTES] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            XteaParams::new(&[0u8; 15]),
            Err(XteaError::InvalidKeyLength(15))
        ));
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = XteaParams::new(&[0xA5u8; XTEA_KEY_BYTES]).unwrap();
        assert_eq!(alloc::format!("{params:?}"), "XteaParams { key_len: 16 }");
    }
}
