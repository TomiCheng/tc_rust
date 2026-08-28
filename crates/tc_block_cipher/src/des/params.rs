//! DES initialization parameters.

use core::fmt;

use super::{DES_KEY_BYTES, BlockCipherError};

/// An owned DES key.
pub struct DesParams {
    key: [u8; DES_KEY_BYTES],
}

impl DesParams {
    /// Copies an 8-byte DES key.
    ///
    /// Parity bits and weak keys are accepted exactly as supplied.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let key = key
            .try_into()
            .map_err(|_| BlockCipherError::InvalidKeyLength(key.len()))?;
        Ok(Self { key })
    }

    pub(crate) const fn key(&self) -> &[u8; DES_KEY_BYTES] {
        &self.key
    }
}

impl fmt::Debug for DesParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DesParams")
            .field("key_len", &DES_KEY_BYTES)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_only_key_length() {
        assert_eq!(
            DesParams::new(&[0u8; 7]).unwrap_err(),
            BlockCipherError::InvalidKeyLength(7)
        );
        assert_eq!(
            DesParams::new(&[0u8; 9]).unwrap_err(),
            BlockCipherError::InvalidKeyLength(9)
        );
        assert!(DesParams::new(&[0x01; 8]).is_ok());
    }

    #[test]
    fn owns_and_redacts_key_material() {
        let params = {
            let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
            DesParams::new(&key).unwrap()
        };
        assert_eq!(
            params.key(),
            &[0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1]
        );
        assert_eq!(alloc::format!("{params:?}"), "DesParams { key_len: 8 }");
    }
}
