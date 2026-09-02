//! Twofish ECB vectors from Bouncy Castle's `TwofishTest.cs`.

mod common;

use common::unhex;
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_params::KeyRef;
use tc_twofish::{BLOCK_BYTES, TwofishEngine};

#[test]
fn bc_ecb_vectors_for_every_key_length() {
    let plaintext = unhex("000102030405060708090a0b0c0d0e0f");
    for (key_hex, ciphertext_hex) in [
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
    ] {
        let key = unhex(key_hex);
        let ciphertext = unhex(ciphertext_hex);
        let params = KeyRef::new(&key);
        let mut engine = TwofishEngine::new();

        engine.init(CipherDirection::Encrypt, &params).unwrap();
        let mut encrypted = [0u8; BLOCK_BYTES];
        assert_eq!(
            engine.process_block(&plaintext, &mut encrypted).unwrap(),
            BLOCK_BYTES
        );
        assert_eq!(encrypted.as_slice(), ciphertext, "key {key_hex}");

        engine.init(CipherDirection::Decrypt, &params).unwrap();
        let mut recovered = [0u8; BLOCK_BYTES];
        engine.process_block(&ciphertext, &mut recovered).unwrap();
        assert_eq!(recovered.as_slice(), plaintext, "key {key_hex}");
    }
}

#[test]
fn zero_key_zero_plaintext_vector() {
    let key = [0u8; 16];
    let mut engine = TwofishEngine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&key))
        .unwrap();

    let mut ciphertext = [0u8; BLOCK_BYTES];
    engine
        .process_block(&[0u8; BLOCK_BYTES], &mut ciphertext)
        .unwrap();
    assert_eq!(
        ciphertext.as_slice(),
        unhex("9f589f5cf6122c32b6bfec2f2ae8c35a")
    );
}
