//! XTEA ECB vectors from Bouncy Castle's `XTEATest.cs`.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_cipher::{XteaEngine, XteaParams};

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
    let params = XteaParams::new(&key).unwrap();
    let mut engine = XteaEngine::new();
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
    run_vector("00000000000000000000000000000000", "0000000000000000", "dee9d4d8f7131ed9");
    run_vector("00000000000000000000000000000000", "0102030405060708", "065c1b8975c6a816");
    run_vector("0123456712345678234567893456789A", "0000000000000000", "1ff9a0261ac64264");
    run_vector("0123456712345678234567893456789A", "0102030405060708", "8c67155b2ef91ead");
}
