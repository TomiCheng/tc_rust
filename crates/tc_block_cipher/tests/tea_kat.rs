//! TEA ECB vectors from Bouncy Castle's `TEATest.cs`.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_cipher::{TeaEngine, TeaParams};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = TeaParams::new(&key).unwrap();
    let mut engine = TeaEngine::new();
    let mut output = vec![0u8; 8];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(engine.process_block(&plaintext, &mut output).unwrap(), 8);
    assert_eq!(output, ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(output, plaintext);
}

#[test]
fn bc_ecb_vectors() {
    run_vector("00000000000000000000000000000000", "0000000000000000", "41ea3a0a94baa940");
    run_vector("00000000000000000000000000000000", "0102030405060708", "6a2f9cf3fccf3c55");
    run_vector("0123456712345678234567893456789A", "0000000000000000", "34e943b0900f5dcb");
    run_vector("0123456712345678234567893456789A", "0102030405060708", "773dc179878a81c0");
}
