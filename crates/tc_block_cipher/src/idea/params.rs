//! Validated IDEA initialization parameters.

use core::fmt;

use super::{IDEA_KEY_BYTES, BlockCipherError};

/// Owned, validated IDEA key parameter (128 bits).
pub struct IdeaParams {
    key: [u8; IDEA_KEY_BYTES],
}

impl fmt::Debug for IdeaParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdeaParams")
            .field("key_len", &IDEA_KEY_BYTES)
            .finish()
    }
}

impl IdeaParams {
    /// Validates that `key` is exactly 16 bytes and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let key: &[u8; IDEA_KEY_BYTES] = key
            .try_into()
            .map_err(|_| BlockCipherError::InvalidKeyLength(key.len()))?;
        Ok(Self { key: *key })
    }

    pub(crate) const fn key(&self) -> &[u8; IDEA_KEY_BYTES] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_key_length() {
        assert!(matches!(
            IdeaParams::new(&[0u8; 15]),
            Err(BlockCipherError::InvalidKeyLength(15))
        ));
        assert!(matches!(
            IdeaParams::new(&[0u8; 32]),
            Err(BlockCipherError::InvalidKeyLength(32))
        ));
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = IdeaParams::new(&[0xA5u8; IDEA_KEY_BYTES]).unwrap();
        assert_eq!(format!("{params:?}"), "IdeaParams { key_len: 16 }");
    }

    #[test]
    fn owned_key_outlives_input() {
        let params = {
            let key = [0x11u8; IDEA_KEY_BYTES];
            IdeaParams::new(&key).unwrap()
        };
        assert_eq!(params.key(), &[0x11u8; IDEA_KEY_BYTES]);
    }
}
