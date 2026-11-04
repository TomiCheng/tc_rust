use crate::params::SecretKey;

// What a MAC's init takes, as plain data: the key and, for the MACs that take one, an IV. Nothing
// here checks its contents; init does
#[derive(Clone, Debug)]
pub struct AnyMacParams {
    key: SecretKey,
    iv: Option<Vec<u8>>,
}

impl AnyMacParams {
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

// The key alone, as most MACs take
impl From<SecretKey> for AnyMacParams {
    fn from(key: SecretKey) -> Self {
        Self::new(key)
    }
}
