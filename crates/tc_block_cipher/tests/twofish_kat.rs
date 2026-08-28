//! Twofish ECB vectors from Bouncy Castle's `TwofishTest.cs`.

use tc_crypto_core::BlockCipher;
use tc_block_cipher::{TwofishEngine, TwofishParams};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn bc_ecb_vectors_encrypt_and_decrypt() {
    let plaintext = unhex("000102030405060708090a0b0c0d0e0f");
    let vectors = [
        (
            "000102030405060708090a0b0c0d0e0f",
            "9fb63337151be9c71306d159ea7afaa4",
        ),
        (
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "95accc625366547617f8be4373d10cd7",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ef0272c42db838bcf7b07af0ec30f38",
        ),
    ];

    for (key_hex, ciphertext_hex) in vectors {
        let key = unhex(key_hex);
        let ciphertext = unhex(ciphertext_hex);
        let params = TwofishParams::new(&key).unwrap();
        let mut engine = TwofishEngine::new();
        let mut output = [0u8; 16];

        engine.init(true, &params).unwrap();
        assert_eq!(engine.process_block(&plaintext, &mut output).unwrap(), 16);
        assert_eq!(output.as_slice(), ciphertext);

        engine.init(false, &params).unwrap();
        engine.process_block(&ciphertext, &mut output).unwrap();
        assert_eq!(output.as_slice(), plaintext);
    }
}

#[test]
fn zero_key_zero_plaintext_vector() {
    let params = TwofishParams::new(&[0u8; 16]).unwrap();
    let mut engine = TwofishEngine::new();
    let mut output = [0u8; 16];

    engine.init(true, &params).unwrap();
    engine.process_block(&[0u8; 16], &mut output).unwrap();
    assert_eq!(output, unhex("9f589f5cf6122c32b6bfec2f2ae8c35a").as_slice());
}
