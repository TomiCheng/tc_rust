//! DSTU 7624 initialization parameters.

use core::fmt;

use super::BlockCipherError;

/// An owned DSTU 7624 key containing exactly `KEY_WORDS` 64-bit words.
///
/// `KEY_WORDS` must be 2, 4, or 8, selecting a 128-, 256-, or 512-bit key
/// without reserving space for larger variants.
pub struct Dstu7624Params<const KEY_WORDS: usize> {
    key_words: [[u8; 8]; KEY_WORDS],
}

impl<const KEY_WORDS: usize> Dstu7624Params<KEY_WORDS> {
    const VALID_KEY_WORDS: () = assert!(
        KEY_WORDS == 2 || KEY_WORDS == 4 || KEY_WORDS == 8,
        "DSTU 7624 KEY_WORDS must be 2, 4, or 8"
    );

    /// Copies a key whose length must equal `KEY_WORDS * 8` bytes.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let () = Self::VALID_KEY_WORDS;
        if key.len() != KEY_WORDS * 8 {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }

        let mut key_words = [[0_u8; 8]; KEY_WORDS];
        for (word, bytes) in key_words.iter_mut().zip(key.chunks_exact(8)) {
            word.copy_from_slice(bytes);
        }
        Ok(Self { key_words })
    }

    /// Returns the selected key length in bytes.
    pub const fn key_len(&self) -> usize {
        KEY_WORDS * 8
    }

    pub(crate) const fn key_words(&self) -> &[[u8; 8]; KEY_WORDS] {
        &self.key_words
    }
}

impl<const KEY_WORDS: usize> fmt::Debug for Dstu7624Params<KEY_WORDS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dstu7624Params")
            .field("key_len", &(KEY_WORDS * 8))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_each_supported_key_width() {
        assert!(Dstu7624Params::<2>::new(&[0_u8; 16]).is_ok());
        assert!(Dstu7624Params::<4>::new(&[0_u8; 32]).is_ok());
        assert!(Dstu7624Params::<8>::new(&[0_u8; 64]).is_ok());
    }

    #[test]
    fn rejects_key_length_that_does_not_match_the_type() {
        assert!(matches!(
            Dstu7624Params::<2>::new(&[0_u8; 32]),
            Err(BlockCipherError::InvalidKeyLength(32))
        ));
        assert!(matches!(
            Dstu7624Params::<4>::new(&[0_u8; 31]),
            Err(BlockCipherError::InvalidKeyLength(31))
        ));
    }

    #[test]
    fn owns_and_redacts_the_exact_key_width() {
        let params = {
            let key = [0xa5_u8; 32];
            Dstu7624Params::<4>::new(&key).unwrap()
        };

        assert_eq!(params.key_len(), 32);
        assert_eq!(format!("{params:?}"), "Dstu7624Params { key_len: 32 }");
        assert_eq!(core::mem::size_of_val(&params), 32);
    }
}
