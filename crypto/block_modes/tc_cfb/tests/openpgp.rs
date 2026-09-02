mod common;

use tc_aes::{AesEngine, BLOCK_BYTES};
use tc_cfb::{CfbBlockCipher, FixedOpenPgpCfbBlockCipher, OpenPgpCfbBlockCipher};
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_crypto::AlgorithmName;

use common::{KeyIv, unhex};

const KEY: &str = "000102030405060708090a0b0c0d0e0f";
const PLAINTEXT: &str = concat!(
    "000102030405060708090a0b0c0d0e0f",
    "101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f",
    "303132333435363738393a3b3c3d3e3f",
);

fn run<M: BlockCipher>(mode: &mut M, input: &[u8]) -> Vec<u8> {
    let block_size = mode.block_size();
    let mut output = vec![0; input.len()];
    for (input, output) in input.chunks(block_size).zip(output.chunks_mut(block_size)) {
        assert_eq!(mode.process_block(input, output).unwrap(), block_size);
    }
    output
}

fn dynamic(direction: CipherDirection, iv: &[u8], input: &[u8]) -> Vec<u8> {
    let key = unhex(KEY);
    let params = KeyIv { key: &key, iv };
    let mut mode = OpenPgpCfbBlockCipher::new(AesEngine::new());
    mode.init(direction, &params).unwrap();
    run(&mut mode, input)
}

fn fixed(direction: CipherDirection, iv: &[u8], input: &[u8]) -> Vec<u8> {
    let key = unhex(KEY);
    let params = KeyIv { key: &key, iv };
    let mut mode = FixedOpenPgpCfbBlockCipher::<AesEngine, BLOCK_BYTES>::new(AesEngine::new());
    mode.init(direction, &params).unwrap();
    run(&mut mode, input)
}

#[test]
fn dynamic_and_fixed_round_trip_across_resynchronization() {
    let iv = [0; BLOCK_BYTES];
    let plaintext = unhex(PLAINTEXT);

    let ciphertext = dynamic(CipherDirection::Encrypt, &iv, &plaintext);
    assert_ne!(ciphertext, plaintext);
    assert_eq!(
        dynamic(CipherDirection::Decrypt, &iv, &ciphertext),
        plaintext
    );
    assert_eq!(fixed(CipherDirection::Encrypt, &iv, &plaintext), ciphertext);
    assert_eq!(fixed(CipherDirection::Decrypt, &iv, &ciphertext), plaintext);
}

#[test]
fn first_block_matches_standard_full_block_cfb() {
    let iv = unhex("0f0e0d0c0b0a09080706050403020100");
    let plaintext = unhex("00112233445566778899aabbccddeeff");
    let openpgp = dynamic(CipherDirection::Encrypt, &iv, &plaintext);

    let key = unhex(KEY);
    let params = KeyIv { key: &key, iv: &iv };
    let mut standard = CfbBlockCipher::new(AesEngine::new(), 128).unwrap();
    standard.init(CipherDirection::Encrypt, &params).unwrap();

    assert_eq!(openpgp, run(&mut standard, &plaintext));
}

#[test]
fn reports_composed_algorithm_name() {
    let mode = OpenPgpCfbBlockCipher::new(AesEngine::new());
    let mut name = String::new();
    mode.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/OpenPGPCFB");
    assert_eq!(mode.block_size(), BLOCK_BYTES);
}
