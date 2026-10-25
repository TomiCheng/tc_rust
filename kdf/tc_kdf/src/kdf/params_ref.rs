use crate::kdf::KdfParams;

/// Borrowed [`KdfParams`]. The caller owns the bytes and wipes them; nothing is checked here,
/// each function checks its parameters in `init`.
#[derive(Clone, Copy)]
pub struct KdfParamsRef<'a> {
    shared_secret: &'a [u8],
    iv: &'a [u8],
}

impl<'a> KdfParamsRef<'a> {
    /// A shared secret without context, as BC's `Iso18033KdfParameters`. Constant time.
    pub const fn new(shared_secret: &'a [u8]) -> Self {
        Self {
            shared_secret,
            iv: &[],
        }
    }

    /// A shared secret with context, as BC's `KdfParameters`. Constant time.
    pub const fn with_iv(shared_secret: &'a [u8], iv: &'a [u8]) -> Self {
        Self { shared_secret, iv }
    }
}

impl KdfParams for KdfParamsRef<'_> {
    /// Constant time: returns the slice without reading it.
    fn shared_secret(&self) -> &[u8] {
        self.shared_secret
    }

    /// Constant time: returns the slice without reading it.
    fn iv(&self) -> &[u8] {
        self.iv
    }
}
