use crate::Ed448PublicKey;
use crate::rfc8032::ed448::ExpandedKey;
use tc_zeroize::Zeroize;

#[derive(Clone)]
pub struct Ed448PrivateKey {
    k: [u8; 57],
}

impl Ed448PrivateKey {
    pub const SIZE: usize = 57;

    pub fn new(k: [u8; 57]) -> Self {
        Self { k }
    }

    pub fn k(&self) -> &[u8; 57] {
        &self.k
    }

    pub fn generate_public_key(&self) -> Ed448PublicKey {
        Ed448PublicKey::new(*ExpandedKey::new(&self.k).public_key())
    }
}

impl Drop for Ed448PrivateKey {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}
