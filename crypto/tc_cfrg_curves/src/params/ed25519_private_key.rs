use crate::Ed25519PublicKey;
use crate::rfc8032::ed25519::ExpandedKey;
use tc_zeroize::Zeroize;

#[derive(Clone)]
pub struct Ed25519PrivateKey {
    k: [u8; 32],
}

impl Ed25519PrivateKey {
    pub const SIZE: usize = 32;

    pub fn new(k: [u8; 32]) -> Self {
        Self { k }
    }

    pub fn k(&self) -> &[u8; 32] {
        &self.k
    }

    pub fn generate_public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::new(*ExpandedKey::new(&self.k).public_key())
    }
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}
