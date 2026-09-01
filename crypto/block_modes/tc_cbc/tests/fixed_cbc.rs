mod common;

use tc_aes::{AesEngine, BLOCK_BYTES};
use tc_cbc::{FixedCbcBlockCipher, Params};
use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockError, BlockModeError, BlockModeInitError,
    CipherDirection, InitError,
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
const CIPHERTEXT: &str = concat!(
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
);

fn aes_cbc(direction: CipherDirection, input: &[u8]) -> Vec<u8> {
    let key = unhex(KEY);
    let iv = unhex(IV);
    let key_params = KeyRef::new(&key);
    let params = Params::<dyn KeyParams>::with_iv(&key_params, &iv);
    let mut mode = FixedCbcBlockCipher::<AesEngine, BLOCK_BYTES>::new(AesEngine::new());
    mode.init(direction, &params).unwrap();

    let mut output = vec![0; input.len()];
    for (input, output) in input
        .chunks(BLOCK_BYTES)
        .zip(output.chunks_mut(BLOCK_BYTES))
    {
        assert_eq!(mode.process_block(input, output), Ok(BLOCK_BYTES));
    }
    output
}

#[test]
fn matches_nist_sp800_38a_aes128_vectors() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = unhex(CIPHERTEXT);

    assert_eq!(aes_cbc(CipherDirection::Encrypt, &plaintext), ciphertext);
    assert_eq!(aes_cbc(CipherDirection::Decrypt, &ciphertext), plaintext);
}

#[test]
fn rejects_a_mismatched_compile_time_block_size() {
    let key = unhex(KEY);
    let key_params = KeyRef::new(&key);
    let params = Params::<dyn KeyParams>::new(&key_params);
    let mut mode = FixedCbcBlockCipher::<AesEngine, 8>::new(AesEngine::new());

    assert_eq!(
        mode.init(CipherDirection::Encrypt, &params),
        Err(BlockModeInitError::<InitError>::UnsupportedBlockSize {
            actual: BLOCK_BYTES,
            required: 8,
        })
    );
}

#[test]
fn exposes_mode_metadata_and_dynamic_dispatch() {
    let mut mode = FixedCbcBlockCipher::<AesEngine, BLOCK_BYTES>::new(AesEngine::new());
    let mut name = String::new();
    mode.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/CBC");
    assert_eq!(mode.block_size(), BLOCK_BYTES);
    assert_eq!(mode.underlying_cipher().block_size(), BLOCK_BYTES);
    assert!(!mode.is_partial_block_okay());

    let mode: &mut dyn BlockCipherMode<Error = BlockModeError<BlockError>, Cipher = AesEngine> =
        &mut mode;
    assert_eq!(mode.block_size(), BLOCK_BYTES);
}
