//! Raw Poly1305 initialization parameters.

use core::fmt;

use super::{KEY_BYTES, Params};

/// Borrowed 32-byte one-time key for raw Poly1305.
///
/// This parameter type does not contain a nonce or block cipher. Poly1305
/// applies the required clamp internally when the engine is initialized.
pub struct BorrowedParams<'a> {
    key: &'a [u8; KEY_BYTES],
}

impl<'a> BorrowedParams<'a> {
    /// Borrows a 32-byte one-time key.
    pub const fn new(key: &'a [u8; KEY_BYTES]) -> Self {
        Self { key }
    }
}

impl Params for BorrowedParams<'_> {
    fn key(&self) -> &[u8; KEY_BYTES] {
        self.key
    }
}

impl fmt::Debug for BorrowedParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BorrowedParams")
            .field("key_len", &self.key.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;

    #[test]
    fn borrows_fixed_length_one_time_key() {
        let key = [0xa5; KEY_BYTES];
        let params = BorrowedParams::new(&key);

        assert!(core::ptr::eq(params.key(), &key));
    }

    #[test]
    fn debug_redacts_key_material() {
        let params = BorrowedParams::new(&[0xa5; KEY_BYTES]);

        assert_eq!(format!("{params:?}"), "BorrowedParams { key_len: 32 }");
    }
}
