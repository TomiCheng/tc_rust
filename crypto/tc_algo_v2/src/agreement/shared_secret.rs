use tc_zeroize::Zeroize;

// The raw secret an agreement calculates, such as g^(xy) mod p for DH. Its bytes are not uniformly
// random, so they are not yet a key, and go through a KDF first. It wipes itself when dropped. No
// Clone, to keep one copy, no ==, which would take time that depends on the bytes, and no Debug,
// which would show them
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl SharedSecret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
