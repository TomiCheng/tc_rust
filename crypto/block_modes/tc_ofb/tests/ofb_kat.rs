mod common;

use core::convert::Infallible;

use tc_aes::{AesEngine, BLOCK_BYTES};
use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeInitError, CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_ofb::{FixedOfbBlockCipher, OfbBlockCipher};

use common::{KeyIv, unhex};

const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const IV: &str = "000102030405060708090a0b0c0d0e0f";
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);
const CIPHERTEXT: &str = concat!(
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "7789508d16918f03f53c52dac54ed825",
    "9740051e9c5fecf64344f7a82260edcc",
    "304c6528f659c77866a510d9c1d6ae5e",
);

fn run<M: BlockCipher>(mode: &mut M, input: &[u8]) -> Vec<u8> {
    let segment = mode.block_size();
    let mut output = vec![0; input.len()];
    for (input, output) in input.chunks(segment).zip(output.chunks_mut(segment)) {
        assert_eq!(mode.process_block(input, output).unwrap(), segment);
    }
    output
}

fn dynamic(direction: CipherDirection, input: &[u8]) -> Vec<u8> {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let mut mode = OfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    mode.init(direction, &KeyIv { key: &key, iv: &iv }).unwrap();
    run(&mut mode, input)
}

fn fixed(direction: CipherDirection, input: &[u8]) -> Vec<u8> {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let mut mode =
        FixedOfbBlockCipher::<AesEngine, BLOCK_BYTES, BLOCK_BYTES>::new(AesEngine::new());
    mode.init(direction, &KeyIv { key: &key, iv: &iv }).unwrap();
    run(&mut mode, input)
}

#[test]
fn dynamic_and_fixed_match_nist_sp800_38a() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = unhex(CIPHERTEXT);

    assert_eq!(dynamic(CipherDirection::Encrypt, &plaintext), ciphertext);
    assert_eq!(dynamic(CipherDirection::Decrypt, &ciphertext), plaintext);
    assert_eq!(fixed(CipherDirection::Encrypt, &plaintext), ciphertext);
    assert_eq!(fixed(CipherDirection::Decrypt, &ciphertext), plaintext);
}

#[test]
fn reset_restarts_the_feedback_register() {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let input = unhex(&PLAINTEXT[..32]);
    let mut mode = OfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    mode.init(CipherDirection::Encrypt, &KeyIv { key: &key, iv: &iv })
        .unwrap();

    let first = run(&mut mode, &input);
    mode.reset();
    assert_eq!(run(&mut mode, &input), first);
}

#[test]
fn validates_feedback_size_and_reports_name() {
    assert!(matches!(
        OfbBlockCipher::new(AesEngine::new(), 0),
        Err(BlockModeInitError::<Infallible>::InvalidFeedbackSize(0))
    ));
    assert!(matches!(
        OfbBlockCipher::new(AesEngine::new(), 12),
        Err(BlockModeInitError::<Infallible>::InvalidFeedbackSize(12))
    ));

    let mode = OfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    let mut name = String::new();
    mode.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/OFB128");
    assert!(mode.is_partial_block_okay());
}
