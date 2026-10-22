use crate::X448PublicKey;
use tc_zeroize::Zeroize;

#[derive(Clone)]
pub struct X448PrivateKey {
    k: [u8; 56],
}

impl X448PrivateKey {
    pub const SIZE: usize = 56;

    pub fn new(k: [u8; 56]) -> Self {
        Self { k }
    }

    pub fn k(&self) -> &[u8; 56] {
        &self.k
    }

    pub fn generate_public_key(&self) -> X448PublicKey {
        todo!()
    }
}

impl Drop for X448PrivateKey {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}
