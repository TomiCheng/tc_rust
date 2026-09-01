mod common;

use tc_aes::{AesEngine, BLOCK_BYTES as AES_BLOCK_BYTES};
use tc_cbc::{CbcBlockCipher, Params};
use tc_cipher::{
    BlockCipher, BlockCipherInit, BlockCipherMode, BlockError, BlockModeError, BlockModeInitError,
    CipherDirection, InitError,
};
use tc_crypto::AlgorithmName;
use tc_des::{BLOCK_BYTES as DES_BLOCK_BYTES, DesEngine};
use tc_params::{KeyParams, KeyRef};

use common::unhex;

const AES_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const AES_IV: &str = "000102030405060708090a0b0c0d0e0f";
const AES_PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);
const AES_CIPHERTEXT: &str = concat!(
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
);

fn aes_cbc(direction: CipherDirection, iv: Option<&[u8]>, input: &[u8]) -> Vec<u8> {
    let key = unhex(AES_KEY);
    let key_params = KeyRef::new(&key);
    let params = match iv {
        Some(iv) => Params::<dyn KeyParams>::with_iv(&key_params, iv),
        None => Params::<dyn KeyParams>::new(&key_params),
    };
    let mut mode = CbcBlockCipher::new(AesEngine::new());
    mode.init(direction, &params).unwrap();

    let mut output = vec![0; input.len()];
    for (input, output) in input
        .chunks(AES_BLOCK_BYTES)
        .zip(output.chunks_mut(AES_BLOCK_BYTES))
    {
        assert_eq!(mode.process_block(input, output), Ok(AES_BLOCK_BYTES));
    }
    output
}

#[test]
fn matches_nist_sp800_38a_aes128_vectors() {
    let iv = unhex(AES_IV);
    let plaintext = unhex(AES_PLAINTEXT);
    let ciphertext = unhex(AES_CIPHERTEXT);

    assert_eq!(
        aes_cbc(CipherDirection::Encrypt, Some(&iv), &plaintext),
        ciphertext
    );
    assert_eq!(
        aes_cbc(CipherDirection::Decrypt, Some(&iv), &ciphertext),
        plaintext
    );
}

#[test]
fn supports_runtime_block_sizes() {
    let key = unhex("0123456789abcdef");
    let iv = unhex("1234567890abcdef");
    let plaintext = unhex("0011223344556677889aabbccddeeff0");
    let key_params = KeyRef::new(&key);
    let params = Params::<dyn KeyParams>::with_iv(&key_params, &iv);
    let mut mode = CbcBlockCipher::new(DesEngine::new());
    mode.init(CipherDirection::Encrypt, &params).unwrap();

    let mut ciphertext = vec![0; plaintext.len()];
    for (input, output) in plaintext
        .chunks(DES_BLOCK_BYTES)
        .zip(ciphertext.chunks_mut(DES_BLOCK_BYTES))
    {
        mode.process_block(input, output).unwrap();
    }
    assert_eq!(ciphertext, unhex("ea2f68f28421d42f78ecb43cd67c0345"));
}

#[test]
fn omitted_iv_is_zero_and_reset_restores_the_initial_iv() {
    let plaintext = &unhex(AES_PLAINTEXT)[..AES_BLOCK_BYTES];
    let zero_iv = [0; AES_BLOCK_BYTES];
    assert_eq!(
        aes_cbc(CipherDirection::Encrypt, None, plaintext),
        aes_cbc(CipherDirection::Encrypt, Some(&zero_iv), plaintext)
    );

    let key = unhex(AES_KEY);
    let iv = unhex(AES_IV);
    let key_params = KeyRef::new(&key);
    let mut mode = CbcBlockCipher::new(AesEngine::new());
    mode.init(
        CipherDirection::Encrypt,
        &Params::<dyn KeyParams>::with_iv(&key_params, &iv),
    )
    .unwrap();
    let mut first = [0; AES_BLOCK_BYTES];
    let mut chained = [0; AES_BLOCK_BYTES];
    let mut reset = [0; AES_BLOCK_BYTES];
    mode.process_block(plaintext, &mut first).unwrap();
    mode.process_block(plaintext, &mut chained).unwrap();
    mode.reset();
    mode.process_block(plaintext, &mut reset).unwrap();
    assert_ne!(chained, first);
    assert_eq!(reset, first);
}

#[test]
fn exposes_mode_metadata() {
    let mut mode = CbcBlockCipher::new(AesEngine::new());
    let mut name = String::new();
    mode.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "AES/CBC");
    assert_eq!(mode.block_size(), AES_BLOCK_BYTES);
    assert_eq!(mode.underlying_cipher().block_size(), AES_BLOCK_BYTES);
    assert!(!mode.is_partial_block_okay());

    let mode: &mut dyn BlockCipherMode<Error = BlockModeError<BlockError>, Cipher = AesEngine> =
        &mut mode;
    assert_eq!(mode.block_size(), AES_BLOCK_BYTES);
}

#[test]
fn reports_initialization_and_processing_errors() {
    let key = unhex(AES_KEY);
    let key_params = KeyRef::new(&key);
    let mut mode = CbcBlockCipher::new(AesEngine::new());
    assert_eq!(
        mode.process_block(&[0; AES_BLOCK_BYTES], &mut [0; AES_BLOCK_BYTES]),
        Err(BlockModeError::NotInitialised)
    );
    assert_eq!(
        mode.init(
            CipherDirection::Encrypt,
            &Params::<dyn KeyParams>::with_iv(&key_params, &[0; AES_BLOCK_BYTES - 1]),
        ),
        Err(BlockModeInitError::InvalidIvLength(AES_BLOCK_BYTES - 1))
    );

    let short_key = KeyRef::new(&[0; 15]);
    assert_eq!(
        mode.init(
            CipherDirection::Encrypt,
            &Params::<dyn KeyParams>::new(&short_key),
        ),
        Err(BlockModeInitError::Cipher(InitError::InvalidKeyLength(15)))
    );
    mode.init(
        CipherDirection::Encrypt,
        &Params::<dyn KeyParams>::new(&key_params),
    )
    .unwrap();
    assert_eq!(
        mode.process_block(&[0; AES_BLOCK_BYTES - 1], &mut [0; AES_BLOCK_BYTES]),
        Err(BlockModeError::BufferTooShort)
    );
}
