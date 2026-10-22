#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    a: [u8; 32],
}

impl Ed25519PublicKey {
    pub const SIZE: usize = 32;

    pub fn new(a: [u8; 32]) -> Self {
        Self { a }
    }

    pub fn a(&self) -> &[u8; 32] {
        &self.a
    }
}
