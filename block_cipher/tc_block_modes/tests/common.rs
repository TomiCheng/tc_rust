//! 各 mode 測試共用的輔助函式與 NIST SP 800-38A 的 AES-128 向量。

// 每個測試檔只用到其中一部分。
#![allow(dead_code)]

use tc_aes::AesEngine;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyParams, KeyRef};
use tc_block_modes::IvOptParams;

/// NIST SP 800-38A 附錄 F 各 mode 共用的 AES-128 金鑰。
pub const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
/// ECB 以外各 mode 在附錄 F 共用的 IV（CTR 例外，另有初始計數器）。
pub const IV: &str = "000102030405060708090a0b0c0d0e0f";
/// 附錄 F 共用的四個明文區塊。
pub const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);

pub fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

/// 只帶金鑰、省略 IV 的參數。
pub struct KeyOnly<'a>(pub &'a [u8]);

impl KeyParams for KeyOnly<'_> {
    fn key(&self) -> &[u8] {
        self.0
    }
}

impl IvOptParams for KeyOnly<'_> {
    fn iv_opt(&self) -> Option<&[u8]> {
        None
    }
}

/// 以 `direction` 初始化後逐段處理 `input`，回傳串接的輸出。
pub fn process<M, P>(mode: &mut M, direction: CipherDirection, params: &P, input: &[u8]) -> Vec<u8>
where
    M: BlockCipher + BlockCipherInit<P>,
    P: ?Sized,
{
    mode.init(direction, params).unwrap();
    let segment = mode.block_size();
    let mut output = vec![0; input.len()];
    for (input, output) in input.chunks(segment).zip(output.chunks_mut(segment)) {
        assert_eq!(mode.process_block(input, output).unwrap(), segment);
    }
    output
}

/// 加密得到 `ciphertext`，解密再還原 `plaintext`。
pub fn assert_vectors<M, P>(mode: &mut M, params: &P, plaintext: &[u8], ciphertext: &[u8])
where
    M: BlockCipher + BlockCipherInit<P>,
    P: ?Sized,
{
    assert_eq!(process(mode, CipherDirection::Encrypt, params, plaintext), ciphertext);
    assert_eq!(process(mode, CipherDirection::Decrypt, params, ciphertext), plaintext);
}

/// 已初始化的 mode 遇到較長的緩衝區時只寫第一段，其餘保持原樣。
pub fn assert_only_the_first_segment_is_written<M: BlockCipher>(mode: &mut M) {
    let segment = mode.block_size();
    let input = [0x5a; 40];
    let mut output = [0xa5; 40];
    assert_eq!(mode.process_block(&input, &mut output).unwrap(), segment);
    assert!(output[segment..].iter().all(|&byte| byte == 0xa5));
}

/// 直接用 AES 加密一個區塊，當作對照組。
pub fn aes_encrypt_block(key: &[u8], block: &[u8]) -> [u8; 16] {
    let mut engine = AesEngine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(key))
        .unwrap();
    let mut output = [0; 16];
    engine.process_block(block, &mut output).unwrap();
    output
}
