use core::any::Any;

use tc_zeroize::Zeroize;

use crate::Params;

// What BLAKE2xs is set to by Xof::init: a key, a salt and a personalization string, each absent
// unless set. Their lengths are for init to judge, not checked here. The key is wiped on drop
#[derive(Clone, Default)]
pub struct Blake2xsParams {
    key: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    personalization: Option<Vec<u8>>,
}

impl Blake2xsParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }

    pub fn with_salt(mut self, salt: Vec<u8>) -> Self {
        self.salt = Some(salt);
        self
    }

    pub fn with_personalization(mut self, personalization: Vec<u8>) -> Self {
        self.personalization = Some(personalization);
        self
    }

    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }

    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    pub fn personalization(&self) -> Option<&[u8]> {
        self.personalization.as_deref()
    }
}

impl Params for Blake2xsParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Drop for Blake2xsParams {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}
