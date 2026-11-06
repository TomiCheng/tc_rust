use alloc::vec::Vec;

use tc_zeroize::Zeroize;

use crate::hkdf::HkdfParams;

/// Owned [`HkdfParams`], wiped on drop; nothing is checked here.
pub struct HkdfParamsOwned {
    ikm: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    skip_extract: bool,
}

impl HkdfParamsOwned {
    /// Extract and expand, as BC's `HkdfParameters(ikm, salt, info)`; an empty `salt` stands for
    /// none. Takes the vectors without copying them. Constant time.
    pub const fn new(ikm: Vec<u8>, salt: Vec<u8>, info: Vec<u8>) -> Self {
        Self {
            ikm,
            salt,
            info,
            skip_extract: false,
        }
    }

    /// Expand only, with `prk` as the pseudorandom key, as BC's `SkipExtractParameters`. Takes
    /// the vectors without copying them. Constant time.
    pub const fn expand_only(prk: Vec<u8>, info: Vec<u8>) -> Self {
        Self {
            ikm: prk,
            salt: Vec::new(),
            info,
            skip_extract: true,
        }
    }
}

impl HkdfParams for HkdfParamsOwned {
    /// Constant time: returns the slice without reading it.
    fn ikm(&self) -> &[u8] {
        &self.ikm
    }

    /// Constant time: returns the slice without reading it.
    fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Constant time: returns the slice without reading it.
    fn info(&self) -> &[u8] {
        &self.info
    }

    /// Constant time.
    fn skip_extract(&self) -> bool {
        self.skip_extract
    }
}

impl Drop for HkdfParamsOwned {
    /// Wipes the bytes. Constant time with respect to them.
    fn drop(&mut self) {
        self.ikm.zeroize();
        self.salt.zeroize();
        self.info.zeroize();
    }
}
