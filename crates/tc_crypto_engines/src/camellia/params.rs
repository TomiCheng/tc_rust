//! Camellia initialization parameters.

use core::fmt;

use super::BlockCipherError;

enum CamelliaKey {
    Camellia128([u8; 16]),
    Camellia192([u8; 24]),
    Camellia256([u8; 32]),
}

/// An owned Camellia-128, Camellia-192, or Camellia-256 key.
pub struct CamelliaParams {
    key: CamelliaKey,
}

impl CamelliaParams {
    /// Copies a 16-, 24-, or 32-byte Camellia key.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let key = match key.len() {
            16 => CamelliaKey::Camellia128(key.try_into().unwrap()),
            24 => CamelliaKey::Camellia192(key.try_into().unwrap()),
            32 => CamelliaKey::Camellia256(key.try_into().unwrap()),
            length => return Err(BlockCipherError::InvalidKeyLength(length)),
        };
        Ok(Self { key })
    }

    /// Returns the key size in bytes without exposing key material.
    pub const fn key_len(&self) -> usize {
        match self.key {
            CamelliaKey::Camellia128(_) => 16,
            CamelliaKey::Camellia192(_) => 24,
            CamelliaKey::Camellia256(_) => 32,
        }
    }

    pub(crate) const fn key(&self) -> &[u8] {
        match &self.key {
            CamelliaKey::Camellia128(key) => key,
            CamelliaKey::Camellia192(key) => key,
            CamelliaKey::Camellia256(key) => key,
        }
    }
}

impl fmt::Debug for CamelliaParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CamelliaParams")
            .field("key_len", &self.key_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_standard_key_lengths() {
        for length in [16, 24, 32] {
            assert_eq!(
                CamelliaParams::new(&alloc::vec![0u8; length])
                    .unwrap()
                    .key_len(),
                length
            );
        }
        for length in [0, 15, 17, 23, 25, 31, 33] {
            assert!(matches!(
                CamelliaParams::new(&alloc::vec![0u8; length]),
                Err(BlockCipherError::InvalidKeyLength(n)) if n == length
            ));
        }
    }

    #[test]
    fn owns_and_redacts_key_material() {
        let params = {
            let key = [0xA5; 24];
            CamelliaParams::new(&key).unwrap()
        };
        assert_eq!(params.key(), &[0xA5; 24]);
        assert_eq!(
            alloc::format!("{params:?}"),
            "CamelliaParams { key_len: 24 }"
        );
    }
}
