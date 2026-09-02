//! TEA and XTEA ECB vectors from Bouncy Castle's `TEATest.cs` and `XTEATest.cs`.

mod common;

use common::unhex;
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_params::KeyRef;
use tc_tea::{BLOCK_BYTES, TeaEngine, XteaEngine};

macro_rules! run_vectors {
    ($engine:ty, $vectors:expr) => {
        for (key_hex, plaintext_hex, ciphertext_hex) in $vectors {
            let key = unhex(key_hex);
            let plaintext = unhex(plaintext_hex);
            let ciphertext = unhex(ciphertext_hex);
            let params = KeyRef::new(&key);
            let mut engine = <$engine>::new();

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
    };
}

#[test]
fn bc_tea_vectors() {
    run_vectors!(
        TeaEngine,
        [
            (
                "00000000000000000000000000000000",
                "0000000000000000",
                "41ea3a0a94baa940",
            ),
            (
                "00000000000000000000000000000000",
                "0102030405060708",
                "6a2f9cf3fccf3c55",
            ),
            (
                "0123456712345678234567893456789A",
                "0000000000000000",
                "34e943b0900f5dcb",
            ),
            (
                "0123456712345678234567893456789A",
                "0102030405060708",
                "773dc179878a81c0",
            ),
        ]
    );
}

#[test]
fn bc_xtea_vectors() {
    run_vectors!(
        XteaEngine,
        [
            (
                "00000000000000000000000000000000",
                "0000000000000000",
                "dee9d4d8f7131ed9",
            ),
            (
                "00000000000000000000000000000000",
                "0102030405060708",
                "065c1b8975c6a816",
            ),
            (
                "0123456712345678234567893456789A",
                "0000000000000000",
                "1ff9a0261ac64264",
            ),
            (
                "0123456712345678234567893456789A",
                "0102030405060708",
                "8c67155b2ef91ead",
            ),
        ]
    );
}
