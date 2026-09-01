//! ARIA known-answer tests from RFC 5794 and Bouncy Castle's `AriaTest.cs`.

mod common;

use common::{Key, unhex};
use tc_aria::{AriaEngine, BLOCK_BYTES};
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};

fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = Key(&key);
    let mut engine = AriaEngine::new();

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = [0u8; BLOCK_BYTES];
    assert_eq!(
        engine.process_block(&plaintext, &mut encrypted).unwrap(),
        BLOCK_BYTES
    );
    assert_eq!(encrypted.as_slice(), ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; BLOCK_BYTES];
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn rfc_5794_all_key_sizes() {
    const PLAINTEXT: &str = "00112233445566778899aabbccddeeff";
    run_vector(
        "000102030405060708090a0b0c0d0e0f",
        PLAINTEXT,
        "d718fbd6ab644c739da95f3be6451778",
    );
    run_vector(
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        PLAINTEXT,
        "26449c1805dbe7aa25a468ce263a9e79",
    );
    run_vector(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        PLAINTEXT,
        "f92bd7c79fb72e2f2b8f80c1972d24fc",
    );
}
