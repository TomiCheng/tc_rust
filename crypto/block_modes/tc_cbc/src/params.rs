//! CBC initialization parameters.

/// Borrowed parameters for CBC initialization.
///
/// `P` is the parameter type accepted by the underlying block cipher. Omitting
/// the IV selects an all-zero IV, matching Bouncy Castle's CBC behavior.
pub struct Params<'a, P: ?Sized> {
    cipher: &'a P,
    iv: Option<&'a [u8]>,
}

impl<'a, P: ?Sized> Params<'a, P> {
    /// Borrows the underlying cipher parameters and selects an all-zero IV.
    pub const fn new(cipher: &'a P) -> Self {
        Self { cipher, iv: None }
    }

    /// Borrows the underlying cipher parameters and IV.
    pub const fn with_iv(cipher: &'a P, iv: &'a [u8]) -> Self {
        Self {
            cipher,
            iv: Some(iv),
        }
    }

    /// Returns the underlying cipher parameters.
    pub const fn cipher(&self) -> &P {
        self.cipher
    }

    /// Returns the IV, or `None` when an all-zero IV was requested.
    pub const fn iv(&self) -> Option<&[u8]> {
        self.iv
    }
}
