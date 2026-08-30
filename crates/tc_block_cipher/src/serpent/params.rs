//! Validated Serpent/Tnepres initialization parameters.

use core::fmt;

use super::{SERPENT_KEY_STEP_BYTES, SERPENT_MAX_KEY_BYTES, SERPENT_MIN_KEY_BYTES, BlockCipherError};

/// Owned, validated Serpent/Tnepres key parameter.
pub struct SerpentParams {
    key: [u8; SERPENT_MAX_KEY_BYTES],
    key_len: usize,
}

impl fmt::Debug for SerpentParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerpentParams")
            .field("key_len", &self.key_len)
            .finish()
    }
}

impl SerpentParams {
    /// Validates the key length and takes an owned copy.
    ///
    /// Bouncy Castle's Serpent engines accept 4–32 bytes in four-byte steps;
    /// shorter keys are padded according to the Serpent specification.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        if !(SERPENT_MIN_KEY_BYTES..=SERPENT_MAX_KEY_BYTES).contains(&key.len())
            || !key.len().is_multiple_of(SERPENT_KEY_STEP_BYTES)
        {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }

        let mut owned = [0u8; SERPENT_MAX_KEY_BYTES];
        owned[..key.len()].copy_from_slice(key);
        Ok(Self {
            key: owned,
            key_len: key.len(),
        })
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_every_bc_key_length() {
        for key_len in (4..=32).step_by(4) {
            assert!(SerpentParams::new(&vec![0u8; key_len]).is_ok());
        }
    }

    #[test]
    fn rejects_out_of_range_and_unaligned_lengths() {
        for key_len in [0, 1, 3, 5, 15, 31, 33, 36] {
            assert!(matches!(
                SerpentParams::new(&vec![0u8; key_len]),
                Err(BlockCipherError::InvalidKeyLength(n)) if n == key_len
            ));
        }
    }

    #[test]
    fn debug_redacts_owned_key() {
        let params = SerpentParams::new(&[0xa5; 20]).unwrap();
        assert_eq!(
            format!("{params:?}"),
            "SerpentParams { key_len: 20 }"
        );
    }
}
