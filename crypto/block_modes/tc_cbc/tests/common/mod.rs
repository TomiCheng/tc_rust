use tc_aes::AesEngine;
use tc_cbc::CbcParams;
use tc_des::DesEngine;
use tc_params::{IvParams, KeyParams};

pub fn unhex(value: &str) -> Vec<u8> {
    let value: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

pub struct KeyIv<'a> {
    pub key: &'a [u8],
    pub iv: &'a [u8],
}

impl KeyParams for KeyIv<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for KeyIv<'_> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

impl CbcParams<AesEngine> for KeyIv<'_> {
    fn cipher_params(&self) -> &(dyn KeyParams + '_) {
        self
    }
}

impl CbcParams<DesEngine> for KeyIv<'_> {
    fn cipher_params(&self) -> &(dyn KeyParams + '_) {
        self
    }
}
