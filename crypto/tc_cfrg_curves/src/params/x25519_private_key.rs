use crate::X25519PublicKey;
use crate::rfc7748::x25519;
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
        X25519PublicKey::new(x25519::generate_public_key(&self.k))
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}
