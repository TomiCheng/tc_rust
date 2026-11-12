use crate::params::SecretKey;

// What init takes, as plain data: each wrapper checks these fields when it is initialized. The key is
// the key that wraps, the KEK. Its row of the table says whether the IV is optional or required
#[derive(Clone, Debug)]
pub struct AnyWrapParams {
    key: SecretKey,
    iv: Option<Vec<u8>>,
}

impl AnyWrapParams {
    pub fn new(key: SecretKey) -> Self {
        Self { key, iv: None }
    }

    pub fn with_iv(mut self, iv: Vec<u8>) -> Self {
        self.iv = Some(iv);
        self
    }

    pub fn key(&self) -> &SecretKey {
        &self.key
    }

    pub fn iv(&self) -> Option<&[u8]> {
        self.iv.as_deref()
    }
}
