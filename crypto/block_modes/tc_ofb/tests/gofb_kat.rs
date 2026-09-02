use core::convert::Infallible;

use tc_aes::AesEngine;
use tc_cipher::{BlockCipher, BlockCipherInit, BlockModeInitError, CipherDirection};
use tc_crypto::AlgorithmName;
use tc_gost28147::{Gost28147Engine, s_box};
use tc_ofb::{GCTR_BLOCK_BYTES, GofbBlockCipher};
use tc_params::{IvParams, KeyParams, SBoxParams};

struct Params<'a> {
    key: &'a [u8],
    iv: &'a [u8],
    s_box: &'a [u8],
}

impl KeyParams for Params<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl IvParams for Params<'_> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

impl SBoxParams for Params<'_> {
    fn s_box(&self) -> &[u8] {
        self.s_box
    }
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn matches_bouncy_castle_gost_vector() {
    let key = unhex("0011223344556677889900112233445566778899001122334455667788990011");
    let iv = unhex("1234567890abcdef");
    let input = unhex("bc350e71aa113457");
    let mut output = [0; GCTR_BLOCK_BYTES];
    let params = Params {
        key: &key,
        iv: &iv,
        s_box: &s_box::DEFAULT,
    };

    let mut mode = GofbBlockCipher::new(Gost28147Engine::new()).unwrap();
    mode.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        mode.process_block(&input, &mut output),
        Ok(GCTR_BLOCK_BYTES)
    );
    assert_eq!(output.as_slice(), unhex("8824c124c4fd1430"));
}

#[test]
fn reports_name_and_rejects_non_64_bit_ciphers() {
    let mode = GofbBlockCipher::new(Gost28147Engine::new()).unwrap();
    let mut name = String::new();
    mode.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "Gost28147/GCTR");

    assert!(matches!(
        GofbBlockCipher::new(AesEngine::new()),
        Err(BlockModeInitError::<Infallible>::UnsupportedBlockSize {
            actual: 16,
            required: 8,
        })
    ));
}
