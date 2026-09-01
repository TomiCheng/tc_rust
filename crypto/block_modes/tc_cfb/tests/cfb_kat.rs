mod common;

use core::convert::Infallible;

use tc_aes::{AesEngine, BLOCK_BYTES};
use tc_cfb::{CfbBlockCipher, FixedCfbBlockCipher, Params};
use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockError, BlockModeError, BlockModeInitError,
    CipherDirection,
};
use tc_crypto::AlgorithmName;
use tc_params::{KeyParams, KeyRef};

use common::unhex;

const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const IV: &str = "000102030405060708090a0b0c0d0e0f";
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);
const CFB128_CIPHERTEXT: &str = concat!(
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "c8a64537a0b3a93fcde3cdad9f1ce58b",
    "26751f67a3cbb140b1808cf187a4f4df",
    "c04b05357c5d1c0eeac4c66f9ff7f2e6",
);

fn run<M: BlockCipher>(mode: &mut M, input: &[u8]) -> Vec<u8> {
    let segment = mode.block_size();
    let mut output = vec![0; input.len()];
    for (input, output) in input.chunks(segment).zip(output.chunks_mut(segment)) {
        assert_eq!(mode.process_block(input, output).unwrap(), segment);
    }
    output
}

fn dynamic(bits: usize, direction: CipherDirection, input: &[u8]) -> Vec<u8> {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let key_params = KeyRef::new(&key);
    let params = Params::<dyn KeyParams>::with_iv(&key_params, &iv);
    let mut mode = CfbBlockCipher::new(AesEngine::new(), bits).unwrap();
    mode.init(direction, &params).unwrap();
    run(&mut mode, input)
}

fn fixed<const S: usize>(direction: CipherDirection, input: &[u8]) -> Vec<u8> {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let key_params = KeyRef::new(&key);
    let params = Params::<dyn KeyParams>::with_iv(&key_params, &iv);
    let mut mode = FixedCfbBlockCipher::<AesEngine, BLOCK_BYTES, S>::new(AesEngine::new());
    mode.init(direction, &params).unwrap();
    run(&mut mode, input)
}

#[test]
fn dynamic_and_fixed_match_nist_cfb128() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = unhex(CFB128_CIPHERTEXT);

    assert_eq!(
        dynamic(128, CipherDirection::Encrypt, &plaintext),
        ciphertext
    );
    assert_eq!(
        dynamic(128, CipherDirection::Decrypt, &ciphertext),
        plaintext
    );
    assert_eq!(
        fixed::<16>(CipherDirection::Encrypt, &plaintext),
        ciphertext
    );
    assert_eq!(
        fixed::<16>(CipherDirection::Decrypt, &ciphertext),
        plaintext
    );
}

#[test]
fn dynamic_and_fixed_match_nist_cfb8() {
    let plaintext = unhex("6bc1bee22e409f96");
    let ciphertext = unhex("3b79424c9c0dd436");

    assert_eq!(dynamic(8, CipherDirection::Encrypt, &plaintext), ciphertext);
    assert_eq!(fixed::<1>(CipherDirection::Encrypt, &plaintext), ciphertext);
}

#[test]
fn short_iv_is_left_padded_with_zeros() {
    let key = unhex(KEY);
    let short_iv = unhex("01020304");
    let full_iv = unhex("00000000000000000000000001020304");
    let key_params = KeyRef::new(&key);
    let plaintext = unhex("6bc1bee22e409f96e93d7e117393172a");

    let mut short = CfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    short
        .init(
            CipherDirection::Encrypt,
            &Params::<dyn KeyParams>::with_iv(&key_params, &short_iv),
        )
        .unwrap();
    let mut full = CfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    full.init(
        CipherDirection::Encrypt,
        &Params::<dyn KeyParams>::with_iv(&key_params, &full_iv),
    )
    .unwrap();

    assert_eq!(run(&mut short, &plaintext), run(&mut full, &plaintext));
}

#[test]
fn validates_feedback_size_and_exposes_metadata() {
    assert!(matches!(
        CfbBlockCipher::new(AesEngine::new(), 0),
        Err(BlockModeInitError::<Infallible>::InvalidFeedbackSize(0))
    ));
    assert!(matches!(
        CfbBlockCipher::new(AesEngine::new(), 12),
        Err(BlockModeInitError::<Infallible>::InvalidFeedbackSize(12))
    ));
    assert!(matches!(
        CfbBlockCipher::new(AesEngine::new(), 256),
        Err(BlockModeInitError::<Infallible>::InvalidFeedbackSize(256))
    ));

    let mut mode = CfbBlockCipher::new(AesEngine::new(), 8).unwrap();
    let mut name = String::new();
    mode.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/CFB8");
    assert_eq!(mode.block_size(), 1);
    assert!(mode.is_partial_block_okay());

    let mode: &mut dyn BlockCipherMode<Error = BlockModeError<BlockError>, Cipher = AesEngine> =
        &mut mode;
    assert_eq!(mode.block_size(), 1);
}
