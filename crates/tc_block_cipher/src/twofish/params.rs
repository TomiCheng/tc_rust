//! Validated Twofish initialization parameters.

use core::fmt;

use super::BlockCipherError;

enum TwofishKey {
    Bits128([u8; 16]),
    Bits192([u8; 24]),
    Bits256([u8; 32]),
}

impl TwofishKey {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Bits128(key) => key,
            Self::Bits192(key) => key,
            Self::Bits256(key) => key,
        }
    }
}

/// Owned, validated Twofish key parameter.
pub struct TwofishParams {
    key: TwofishKey,
}

impl fmt::Debug for TwofishParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TwofishParams")
            .field("key_len", &self.key().len())
            .finish()
    }
}

impl TwofishParams {
    /// Validates a 128-, 192-, or 256-bit key and takes an owned copy.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let key = match key.len() {
            16 => TwofishKey::Bits128(key.try_into().unwrap()),
            24 => TwofishKey::Bits192(key.try_into().unwrap()),
            32 => TwofishKey::Bits256(key.try_into().unwrap()),
            n => return Err(BlockCipherError::InvalidKeyLength(n)),
        };
        Ok(Self { key })
    }

    pub(crate) fn key(&self) -> &[u8] {
        self.key.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_all_standard_key_lengths() {
        for key_len in [16, 24, 32] {
            assert!(TwofishParams::new(&vec![0u8; key_len]).is_ok());
        }
    }

    #[test]
    fn rejects_invalid_key_lengths() {
        for key_len in [0, 15, 17, 23, 25, 31, 33] {
            assert!(matches!(
                TwofishParams::new(&vec![0u8; key_len]),
                Err(BlockCipherError::InvalidKeyLength(n)) if n == key_len
            ));
        }
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = TwofishParams::new(&[0xa5; 24]).unwrap();
        assert_eq!(
            format!("{params:?}"),
            "TwofishParams { key_len: 24 }"
        );
    }
}
