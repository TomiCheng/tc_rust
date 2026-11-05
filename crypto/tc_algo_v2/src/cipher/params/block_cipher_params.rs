use core::any::Any;

use tc_zeroize::Zeroize;

use crate::Params;

#[derive(Default)]
pub struct BlockCipherParams {
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
}

impl BlockCipherParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_key(mut self, key: &[u8]) -> Self {
        self.key.zeroize();
        self.key = key.to_vec();
        self
    }

    pub fn with_iv(mut self, iv: &[u8]) -> Self {
        self.iv.zeroize();
        self.iv = Some(iv.to_vec());
        self
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn iv(&self) -> Option<&[u8]> {
        self.iv.as_deref()
    }
}

impl Drop for BlockCipherParams {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Params for BlockCipherParams {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::BlockCipherParams;

    const KEY: [u8; 16] = [0x11; 16];
    const IV: [u8; 16] = [0x22; 16];

    #[test]
    fn with_key_and_with_iv_keep_what_they_are_given() {
        let params = BlockCipherParams::new().with_key(&KEY).with_iv(&IV);
        assert_eq!(params.key(), KEY);
        assert_eq!(params.iv(), Some(&IV[..]));
    }

    #[test]
    fn an_iv_that_was_not_given_is_none() {
        let params = BlockCipherParams::new().with_key(&KEY);
        assert_eq!(params.iv(), None);
    }

    #[test]
    fn a_later_with_key_or_with_iv_replaces_the_earlier_value() {
        let params = BlockCipherParams::new()
            .with_key(&[0x33; 16])
            .with_iv(&[0x44; 16])
            .with_key(&KEY)
            .with_iv(&IV);
        assert_eq!(params.key(), KEY);
        assert_eq!(params.iv(), Some(&IV[..]));
    }
}
