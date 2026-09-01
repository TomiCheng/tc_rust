//! CAST5 vectors from RFC 2144 and Bouncy Castle's `Cast5Test.cs`.

mod common;

use common::unhex;
use tc_cast::{Cast5Engine, cast5};
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_params::KeyRef;

#[test]
fn rfc_2144_all_round_counts() {
    let plaintext = unhex("0123456789ABCDEF");
    for (key, ciphertext) in [
        ("0123456712345678234567893456789A", "238B4FE5847E44B2"),
        ("01234567123456782345", "EB6A711A2C02271B"),
        ("0123456712", "7AC816D16E9B302E"),
    ] {
        let key = unhex(key);
        let ciphertext = unhex(ciphertext);
        let params = KeyRef::new(&key);
        let mut engine = Cast5Engine::new();

        engine.init(CipherDirection::Encrypt, &params).unwrap();
        let mut encrypted = [0u8; cast5::BLOCK_BYTES];
        engine.process_block(&plaintext, &mut encrypted).unwrap();
        assert_eq!(encrypted.as_slice(), ciphertext);

        engine.init(CipherDirection::Decrypt, &params).unwrap();
        let mut recovered = [0u8; cast5::BLOCK_BYTES];
        engine.process_block(&ciphertext, &mut recovered).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }
}

#[test]
fn reinitialising_switches_between_reduced_and_full_rounds() {
    let plaintext = unhex("0123456789ABCDEF");
    let short_key = unhex("01234567123456782345");
    let long_key = unhex("0123456712345678234567893456789A");
    let mut engine = Cast5Engine::new();

    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&short_key))
        .unwrap();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&long_key))
        .unwrap();

    let mut encrypted = [0u8; cast5::BLOCK_BYTES];
    engine.process_block(&plaintext, &mut encrypted).unwrap();
    assert_eq!(encrypted.as_slice(), unhex("238B4FE5847E44B2"));
}
