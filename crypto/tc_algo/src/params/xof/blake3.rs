use core::any::Any;

use tc_zeroize::Zeroize;

use crate::Params;

// What BLAKE3 is set to by Xof::init, after Bouncy Castle's Blake3Parameters: a key, for the keyed
// hash, or a context string, for key derivation. The key's length is for init to judge, not
// checked here, and it is wiped on drop
#[derive(Clone)]
pub struct Blake3Params {
    key: Option<Vec<u8>>,
    context: Option<Vec<u8>>,
}

impl Blake3Params {
    pub fn keyed(key: Vec<u8>) -> Self {
        Self {
            key: Some(key),
            context: None,
        }
    }

    pub fn derive_key(context: Vec<u8>) -> Self {
        Self {
            key: None,
            context: Some(context),
        }
    }

    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }

    pub fn context(&self) -> Option<&[u8]> {
        self.context.as_deref()
    }
}

impl Params for Blake3Params {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Drop for Blake3Params {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}
