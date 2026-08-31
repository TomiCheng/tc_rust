//! Raw Poly1305 initialization parameters.

use core::fmt;

use tc_crypto_core::{Iv, Key};

use super::{CIPHER_KEY_BYTES, KEY_BYTES, NONCE_BYTES};

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

impl Key for BorrowedParams<'_> {
    fn key(&self) -> &[u8] {
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

/// Parameters for Poly1305 with an underlying 128-bit block cipher.
///
/// The 32-byte Poly1305 key is split conceptually into a 16-byte polynomial
/// key and a 16-byte block-cipher key. [`try_new`](Self::try_new) passes the
/// latter half to `build_cipher_params`, ensuring that callers can construct
/// the underlying cipher's own strongly typed parameter object.
pub struct CipherParams<'a, P> {
    key: &'a [u8; KEY_BYTES],
    iv: &'a [u8; NONCE_BYTES],
    cipher_params: P,
}

impl<'a, P> CipherParams<'a, P> {
    /// Builds the underlying cipher parameters from the last 16 key bytes.
    pub fn try_new<E>(
        key: &'a [u8; KEY_BYTES],
        iv: &'a [u8; NONCE_BYTES],
        build_cipher_params: impl FnOnce(&'a [u8; CIPHER_KEY_BYTES]) -> Result<P, E>,
    ) -> Result<Self, E> {
        let cipher_key: &'a [u8; CIPHER_KEY_BYTES] = key[KEY_BYTES - CIPHER_KEY_BYTES..]
            .try_into()
            .expect("the Poly1305 cipher-key range is always 16 bytes");
        let cipher_params = build_cipher_params(cipher_key)?;

        Ok(Self {
            key,
            iv,
            cipher_params,
        })
    }

    pub(super) const fn key(&self) -> &[u8; KEY_BYTES] {
        self.key
    }

    pub(super) const fn iv(&self) -> &[u8; NONCE_BYTES] {
        self.iv
    }

    pub(super) const fn cipher_params(&self) -> &P {
        &self.cipher_params
    }
}

impl<P> Key for CipherParams<'_, P> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl<P> Iv for CipherParams<'_, P> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

impl<P> fmt::Debug for CipherParams<'_, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherParams")
            .field("key_len", &self.key.len())
            .field("iv_len", &self.iv.len())
            .finish_non_exhaustive()
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

    #[test]
    fn cipher_params_receive_second_key_half_and_redact_material() {
        let key = core::array::from_fn(|index| index as u8);
        let iv = [0xa5; NONCE_BYTES];
        let params = CipherParams::try_new(&key, &iv, |cipher_key| {
            Ok::<_, core::convert::Infallible>(cipher_key)
        })
        .unwrap();

        assert_eq!(Key::key(&params), &key);
        assert_eq!(Iv::iv(&params), &iv);
        assert_eq!(*params.cipher_params(), &key[16..]);
        assert_eq!(
            format!("{params:?}"),
            "CipherParams { key_len: 32, iv_len: 16, .. }"
        );
    }
}
