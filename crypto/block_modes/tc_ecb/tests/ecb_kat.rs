mod common;

use tc_aes::{AesEngine, BLOCK_BYTES};
use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockError, CipherDirection, InitError,
};
use tc_crypto::AlgorithmName;
use tc_ecb::EcbBlockCipher;
use tc_params::KeyRef;

use common::unhex;

const PLAINTEXT: &str = "00112233445566778899aabbccddeeff";
const KEY128: &str = "000102030405060708090a0b0c0d0e0f";
const KEY256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn encrypt(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut mode = EcbBlockCipher::new(AesEngine::new());
    mode.init(CipherDirection::Encrypt, &KeyRef::new(key))
        .unwrap();
    let mut output = vec![0; BLOCK_BYTES];
    assert_eq!(mode.process_block(input, &mut output), Ok(BLOCK_BYTES));
    output
}

#[test]
fn matches_fips_197_aes_vectors() {
    let plaintext = unhex(PLAINTEXT);
    assert_eq!(
        encrypt(&unhex(KEY128), &plaintext),
        unhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    );
    assert_eq!(
        encrypt(&unhex(KEY256), &plaintext),
        unhex("8ea2b7ca516745bfeafc49904b496089")
    );
}

#[test]
fn matches_bare_cipher_and_round_trips() {
    let key = unhex(KEY128);
    let plaintext = unhex(PLAINTEXT);
    let params = KeyRef::new(&key);

    let mut bare = AesEngine::new();
    bare.init(CipherDirection::Encrypt, &params).unwrap();
    let mut bare_output = [0; BLOCK_BYTES];
    bare.process_block(&plaintext, &mut bare_output).unwrap();

    let mut mode = EcbBlockCipher::new(AesEngine::new());
    mode.init(CipherDirection::Encrypt, &params).unwrap();
    let mut ciphertext = [0; BLOCK_BYTES];
    mode.process_block(&plaintext, &mut ciphertext).unwrap();
    assert_eq!(ciphertext, bare_output);

    mode.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0; BLOCK_BYTES];
    mode.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn exposes_mode_metadata_without_allocation() {
    let mut mode = EcbBlockCipher::new(AesEngine::new());
    let mut name = String::new();
    mode.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/ECB");
    assert_eq!(mode.block_size(), BLOCK_BYTES);
    assert_eq!(mode.underlying_cipher().block_size(), BLOCK_BYTES);
    assert!(!mode.is_partial_block_okay());
    mode.reset();

    let mode: &mut dyn BlockCipherMode<Error = BlockError, Cipher = AesEngine> = &mut mode;
    assert_eq!(mode.block_size(), BLOCK_BYTES);
}

#[test]
fn forwards_initialization_and_processing_errors() {
    let mut mode = EcbBlockCipher::new(AesEngine::new());
    assert_eq!(
        mode.process_block(&[0; BLOCK_BYTES], &mut [0; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );
    assert_eq!(
        mode.init(CipherDirection::Encrypt, &KeyRef::new(&[0; 15])),
        Err(InitError::InvalidKeyLength(15))
    );
    mode.init(CipherDirection::Encrypt, &KeyRef::new(&[0; 16]))
        .unwrap();
    assert_eq!(
        mode.process_block(&[0; BLOCK_BYTES - 1], &mut [0; BLOCK_BYTES]),
        Err(BlockError::BufferTooShort)
    );
}
