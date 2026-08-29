//! SKIPJACK ECB vector from Bouncy Castle's `SkipjackTest.cs`.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_cipher::{SkipjackEngine, SkipjackParams};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn bc_ecb_vector() {
    let key = unhex("00998877665544332211");
    let plaintext = unhex("33221100ddccbbaa");
    let ciphertext = unhex("2587cae27a12d300");
    let params = SkipjackParams::new(&key).unwrap();
    let mut engine = SkipjackEngine::new();
    let mut output = vec![0u8; 8];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(engine.process_block(&plaintext, &mut output).unwrap(), 8);
    assert_eq!(output, ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    engine.process_block(&ciphertext, &mut output).unwrap();
    assert_eq!(output, plaintext);
}
