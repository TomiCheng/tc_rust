//! ARIA known-answer tests from RFC 5794 and Bouncy Castle's `AriaTest.cs`.

mod common;

use common::unhex;
use tc_aria::{AriaEngine, AriaTableEngine, BLOCK_BYTES};
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
};

fn run_vector_with<E>(mut engine: E, key: &str, plaintext: &str, ciphertext: &str)
where
    E: BlockCipher<Error = BlockError> + for<'a> BlockCipherInit<KeyRef<'a>, Error = InitError>,
{
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = KeyRef::new(&key);

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

fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    run_vector_with(AriaEngine::new(), key, plaintext, ciphertext);
    run_vector_with(AriaTableEngine::new(), key, plaintext, ciphertext);
    #[cfg(feature = "rustcrypto")]
    run_vector_with(
        tc_aria::AriaRustCryptoEngine::new(),
        key,
        plaintext,
        ciphertext,
    );
}

#[test]
fn rfc_5794_vectors_encrypt_and_decrypt_under_all_three_key_sizes() {
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
