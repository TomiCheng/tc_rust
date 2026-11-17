use alloc::vec::Vec;

use tc_zeroize::Zeroize;

use crate::kdf::KdfParams;

/// Owned [`KdfParams`], wiped on drop; nothing is checked here.
pub struct KdfParamsOwned {
    shared_secret: Vec<u8>,
    iv: Vec<u8>,
}

impl KdfParamsOwned {
    /// A shared secret without context, as BC's `Iso18033KdfParameters`. Takes the vector without
    /// copying it. Constant time.
    pub const fn new(shared_secret: Vec<u8>) -> Self {
        Self {
            shared_secret,
            iv: Vec::new(),
        }
    }

    /// A shared secret with context, as BC's `KdfParameters`. Takes the vectors without copying
    /// them. Constant time.
    pub const fn with_iv(shared_secret: Vec<u8>, iv: Vec<u8>) -> Self {
        Self { shared_secret, iv }
    }
}

impl KdfParams for KdfParamsOwned {
    /// Constant time: returns the slice without reading it.
    fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }

    /// Constant time: returns the slice without reading it.
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl Drop for KdfParamsOwned {
    /// Wipes the bytes. Constant time with respect to them.
    fn drop(&mut self) {
        self.shared_secret.zeroize();
        self.iv.zeroize();
    }
}
