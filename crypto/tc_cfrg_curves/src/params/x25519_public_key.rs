#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey {
    u: [u8; 32],
}

impl X25519PublicKey {
    pub const SIZE: usize = 32;

    pub fn new(u: [u8; 32]) -> Self {
        Self { u }
    }

    pub fn u(&self) -> &[u8; 32] {
        &self.u
    }
}
