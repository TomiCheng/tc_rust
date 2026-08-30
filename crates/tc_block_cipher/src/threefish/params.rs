//! Validated Threefish init parameters.

use core::fmt;

use super::{BlockCipherError, TWEAK_BYTES, valid_word_count};

/// Validated Threefish key and tweak for a `WORDS`-word block.
///
/// `WORDS` must be 4, 8, or 16, selecting Threefish-256, Threefish-512, or
/// Threefish-1024 respectively. The key is converted to words when the
/// parameters are built, so each parameter value stores exactly the selected
/// variant's key material rather than the largest possible key.
pub struct ThreefishParams<const WORDS: usize> {
    key_words: [u64; WORDS],
    tweak_words: [u64; 2],
}

impl<const WORDS: usize> fmt::Debug for ThreefishParams<WORDS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreefishParams")
            .field("key_len", &(WORDS * 8))
            .finish_non_exhaustive()
    }
}

impl<const WORDS: usize> ThreefishParams<WORDS> {
    const VALID_WORD_COUNT: () = assert!(
        valid_word_count(WORDS),
        "Threefish WORDS must be 4, 8, or 16"
    );

    /// Copies and validates a key and optional 16-byte tweak.
    ///
    /// The key must contain exactly `WORDS * 8` bytes. A missing tweak is
    /// normalized to the all-zero tweak, which is cryptographically identical
    /// to supplying sixteen zero bytes.
    pub fn new(key: &[u8], tweak: Option<&[u8]>) -> Result<Self, BlockCipherError> {
        let () = Self::VALID_WORD_COUNT;
        let key_len = WORDS * 8;
        if key.len() != key_len {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }

        let mut key_words = [0_u64; WORDS];
        for (word, bytes) in key_words.iter_mut().zip(key.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().unwrap());
        }

        let mut tweak_words = [0_u64; 2];
        if let Some(tweak) = tweak {
            if tweak.len() != TWEAK_BYTES {
                return Err(BlockCipherError::InvalidTweakLength(tweak.len()));
            }
            tweak_words[0] = u64::from_le_bytes(tweak[..8].try_into().unwrap());
            tweak_words[1] = u64::from_le_bytes(tweak[8..].try_into().unwrap());
        }

        Ok(Self {
            key_words,
            tweak_words,
        })
    }

    /// Returns the key size in bytes, which is also the block size.
    pub const fn key_len(&self) -> usize {
        WORDS * 8
    }

    pub(crate) const fn key_words(&self) -> &[u64; WORDS] {
        &self.key_words
    }

    pub(crate) const fn tweak_words(&self) -> &[u64; 2] {
        &self.tweak_words
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_each_supported_word_count() {
        assert!(ThreefishParams::<4>::new(&[0_u8; 32], None).is_ok());
        assert!(ThreefishParams::<8>::new(&[0_u8; 64], None).is_ok());
        assert!(ThreefishParams::<16>::new(&[0_u8; 128], None).is_ok());
    }

    #[test]
    fn rejects_key_length_that_does_not_match_the_type() {
        assert!(matches!(
            ThreefishParams::<4>::new(&[0_u8; 31], None),
            Err(BlockCipherError::InvalidKeyLength(31))
        ));
        assert!(matches!(
            ThreefishParams::<8>::new(&[0_u8; 32], None),
            Err(BlockCipherError::InvalidKeyLength(32))
        ));
    }

    #[test]
    fn accepts_and_normalizes_tweak() {
        let key = [0_u8; 32];
        let tweak = [0x5a_u8; 16];
        let params = ThreefishParams::<4>::new(&key, Some(&tweak)).unwrap();
        assert_eq!(params.tweak_words(), &[0x5a5a_5a5a_5a5a_5a5a; 2]);

        let params = ThreefishParams::<4>::new(&key, None).unwrap();
        assert_eq!(params.tweak_words(), &[0; 2]);
    }

    #[test]
    fn rejects_bad_tweak_length() {
        assert!(matches!(
            ThreefishParams::<4>::new(&[0_u8; 32], Some(&[0_u8; 8])),
            Err(BlockCipherError::InvalidTweakLength(8))
        ));
    }

    #[test]
    fn debug_redacts_key_and_tweak_material() {
        let params = ThreefishParams::<4>::new(&[0xa5_u8; 32], Some(&[0x5a_u8; 16])).unwrap();
        assert_eq!(format!("{params:?}"), "ThreefishParams { key_len: 32, .. }");
    }

    #[test]
    fn storage_scales_with_the_selected_key_width() {
        assert_eq!(core::mem::size_of::<ThreefishParams<4>>(), 6 * 8);
        assert_eq!(core::mem::size_of::<ThreefishParams<8>>(), 10 * 8);
        assert_eq!(core::mem::size_of::<ThreefishParams<16>>(), 18 * 8);
    }
}
