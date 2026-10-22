#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X448PublicKey {
    u: [u8; 56],
}

impl X448PublicKey {
    pub const SIZE: usize = 56;

    pub fn new(u: [u8; 56]) -> Self {
        Self { u }
    }

    pub fn u(&self) -> &[u8; 56] {
        &self.u
    }
}
