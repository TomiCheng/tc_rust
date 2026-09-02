mod common;

use tc_aes::{AesEngine, BLOCK_BYTES};
use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockModeError, BlockModeInitError,
    CipherDirection, StreamCipher, StreamCipherInit,
};
use tc_crypto::AlgorithmName;
use tc_ctr::{FixedSicBlockCipher, SicBlockCipher};

use common::{KeyIv, unhex};

const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);
const CIPHERTEXT: &str = concat!(
    "874d6191b620e3261bef6864990db6ce",
    "9806f66b7970fdff8617187bb9fffdff",
    "5ae4df3edbd5d35e5b4f09020db03eab",
    "1e031dda2fbe03d1792170a0f3009cee",
);

fn process_blocks<M: BlockCipher>(mode: &mut M, input: &[u8]) -> Vec<u8> {
    let block_size = mode.block_size();
    let mut output = vec![0; input.len()];
    for (input, output) in input.chunks(block_size).zip(output.chunks_mut(block_size)) {
        assert_eq!(mode.process_block(input, output).unwrap(), block_size);
    }
    output
}

#[test]
fn dynamic_and_fixed_match_nist_sp800_38a() {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = unhex(CIPHERTEXT);
    let params = KeyIv { key: &key, iv: &iv };

    let mut dynamic = SicBlockCipher::new(AesEngine::new());
    BlockCipherInit::init(&mut dynamic, CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(process_blocks(&mut dynamic, &plaintext), ciphertext);

    let mut fixed = FixedSicBlockCipher::<AesEngine, BLOCK_BYTES>::new(AesEngine::new());
    BlockCipherInit::init(&mut fixed, CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(process_blocks(&mut fixed, &ciphertext), plaintext);
}

#[test]
fn stream_interface_handles_unaligned_data_and_reset() {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let input = unhex("00112233445566778899aabbccddeeff010203");
    let params = KeyIv { key: &key, iv: &iv };
    let mut mode = SicBlockCipher::new(AesEngine::new());
    StreamCipherInit::init(&mut mode, CipherDirection::Encrypt, &params).unwrap();

    let mut first = vec![0; input.len()];
    mode.process_bytes(&input, &mut first).unwrap();
    StreamCipher::reset(&mut mode);
    let mut second = vec![0; input.len()];
    mode.process_bytes(&input, &mut second).unwrap();
    assert_eq!(first, second);

    let mut decrypt = SicBlockCipher::new(AesEngine::new());
    StreamCipherInit::init(&mut decrypt, CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = vec![0; input.len()];
    decrypt.process_bytes(&first, &mut recovered).unwrap();
    assert_eq!(recovered, input);
}

#[test]
fn validates_iv_and_exposes_metadata() {
    let key = unhex(KEY);
    let short_iv = [0; 7];
    let params = KeyIv {
        key: &key,
        iv: &short_iv,
    };
    let mut mode = SicBlockCipher::new(AesEngine::new());
    assert!(matches!(
        BlockCipherInit::init(&mut mode, CipherDirection::Encrypt, &params),
        Err(BlockModeInitError::InvalidIvLength(7))
    ));
    assert!(matches!(
        mode.process_block(&[0; BLOCK_BYTES], &mut [0; BLOCK_BYTES]),
        Err(BlockModeError::NotInitialised)
    ));

    let mut name = String::new();
    mode.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/SIC");
    assert!(mode.is_partial_block_okay());
}
