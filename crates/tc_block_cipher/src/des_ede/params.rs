//! Triple DES initialization parameters.

use core::fmt;

use super::{DES_EDE_THREE_KEY_BYTES, DES_EDE_TWO_KEY_BYTES, BlockCipherError};

enum KeyMaterial {
    TwoKey([u8; DES_EDE_TWO_KEY_BYTES]),
    ThreeKey([u8; DES_EDE_THREE_KEY_BYTES]),
}

/// An owned two-key or three-key Triple DES key.
pub struct DesEdeParams {
    key: KeyMaterial,
}

impl DesEdeParams {
    /// Copies a 16-byte (`K1, K2`) or 24-byte (`K1, K2, K3`) key.
    ///
    /// The 16-byte form is processed as `K1, K2, K1`. No parity, weak-key, or
    /// component-distinctness policy is imposed.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let key = match key.len() {
            DES_EDE_TWO_KEY_BYTES => KeyMaterial::TwoKey(key.try_into().unwrap()),
            DES_EDE_THREE_KEY_BYTES => KeyMaterial::ThreeKey(key.try_into().unwrap()),
            length => return Err(BlockCipherError::InvalidKeyLength(length)),
        };
        Ok(Self { key })
    }

    pub(crate) fn key(&self) -> &[u8] {
        match &self.key {
            KeyMaterial::TwoKey(key) => key,
            KeyMaterial::ThreeKey(key) => key,
        }
    }
}

impl fmt::Debug for DesEdeParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DesEdeParams")
            .field("key_len", &self.key().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_two_key_and_three_key_lengths() {
        assert!(DesEdeParams::new(&[0u8; 16]).is_ok());
        assert!(DesEdeParams::new(&[0u8; 24]).is_ok());
        for length in [0, 8, 15, 17, 23, 25] {
            assert_eq!(
                DesEdeParams::new(&alloc::vec![0u8; length]).unwrap_err(),
                BlockCipherError::InvalidKeyLength(length)
            );
        }
    }

    #[test]
    fn owns_and_redacts_key_material() {
        let params = {
            let key = [0xA5; 24];
            DesEdeParams::new(&key).unwrap()
        };
        assert_eq!(params.key(), &[0xA5; 24]);
        assert_eq!(alloc::format!("{params:?}"), "DesEdeParams { key_len: 24 }");
    }
}
