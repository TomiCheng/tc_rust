#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed448PublicKey {
    a: [u8; 57],
}

impl Ed448PublicKey {
    pub const SIZE: usize = 57;

    pub fn new(a: [u8; 57]) -> Self {
        Self { a }
    }

    pub fn a(&self) -> &[u8; 57] {
        &self.a
    }
}
