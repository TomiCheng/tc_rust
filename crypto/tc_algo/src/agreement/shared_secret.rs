use core::fmt;

use tc_zeroize::Zeroize;

// The raw secret an agreement calculates, such as g^(xy) mod p for DH. It is not yet a key: its
// bytes are not uniformly random, so they go through a KDF first. It is not a SecretKey, so it
// cannot go to a cipher as it is. No Clone, to keep one copy, and no ==, which would take time
// that depends on the bytes
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl SharedSecret {
    // As many zeros as the agreement gives, for it to write over
    pub(super) fn zeroed(len: usize) -> Self {
        Self {
            bytes: vec![0; len],
        }
    }

    pub(super) fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// Wipes the bytes this holds, as SecretKey does
impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// Shows the length, never the bytes
impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecret")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
