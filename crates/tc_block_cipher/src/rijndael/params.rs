//! Validated Rijndael initialization parameters.

use core::fmt;

use super::BlockCipherError;

/// An owned Rijndael key containing exactly `KEY_COLUMNS` 32-bit columns.
///
/// `KEY_COLUMNS` must be in `4..=8`, selecting a 128-, 160-, 192-, 224-, or
/// 256-bit key without reserving space for larger variants.
pub struct RijndaelParams<const KEY_COLUMNS: usize> {
    key_columns: [[u8; 4]; KEY_COLUMNS],
}

impl<const KEY_COLUMNS: usize> fmt::Debug for RijndaelParams<KEY_COLUMNS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RijndaelParams")
            .field("key_len", &(KEY_COLUMNS * 4))
            .finish()
    }
}

impl<const KEY_COLUMNS: usize> RijndaelParams<KEY_COLUMNS> {
    const VALID_KEY_COLUMNS: () = assert!(
        KEY_COLUMNS >= 4 && KEY_COLUMNS <= 8,
        "Rijndael KEY_COLUMNS must be in 4..=8"
    );

    /// Copies a key whose length must equal `KEY_COLUMNS * 4` bytes.
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        let () = Self::VALID_KEY_COLUMNS;
        let required = KEY_COLUMNS * 4;
        if key.len() != required {
            return Err(BlockCipherError::InvalidKeyLength(key.len()));
        }

        let mut key_columns = [[0_u8; 4]; KEY_COLUMNS];
        for (column, bytes) in key_columns.iter_mut().zip(key.chunks_exact(4)) {
            column.copy_from_slice(bytes);
        }
        Ok(Self { key_columns })
    }

    /// Returns the selected key length in bytes.
    pub const fn key_len(&self) -> usize {
        KEY_COLUMNS * 4
    }

    pub(crate) const fn key_columns(&self) -> &[[u8; 4]; KEY_COLUMNS] {
        &self.key_columns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_each_supported_key_width() {
        assert!(RijndaelParams::<4>::new(&[0_u8; 16]).is_ok());
        assert!(RijndaelParams::<5>::new(&[0_u8; 20]).is_ok());
        assert!(RijndaelParams::<6>::new(&[0_u8; 24]).is_ok());
        assert!(RijndaelParams::<7>::new(&[0_u8; 28]).is_ok());
        assert!(RijndaelParams::<8>::new(&[0_u8; 32]).is_ok());
    }

    #[test]
    fn rejects_key_length_that_does_not_match_the_type() {
        assert!(matches!(
            RijndaelParams::<4>::new(&[0_u8; 20]),
            Err(BlockCipherError::InvalidKeyLength(20))
        ));
    }

    #[test]
    fn owns_and_redacts_the_exact_key_width() {
        let params = {
            let key = [0xa5_u8; 20];
            RijndaelParams::<5>::new(&key).unwrap()
        };

        assert_eq!(params.key_len(), 20);
        assert_eq!(format!("{params:?}"), "RijndaelParams { key_len: 20 }");
        assert_eq!(core::mem::size_of_val(&params), 20);
    }
}
