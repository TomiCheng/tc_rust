use crate::X25519PublicKey;
use tc_zeroize::Zeroize;

#[derive(Clone)]
pub struct X25519PrivateKey {
    k: [u8; 32],
}

impl X25519PrivateKey {
    pub const SIZE: usize = 32;

    pub fn new(k: [u8; 32]) -> Self {
        Self { k }
    }

    pub fn k(&self) -> &[u8; 32] {
        &self.k
    }

    pub fn generate_public_key(&self) -> X25519PublicKey {
        todo!()
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}
