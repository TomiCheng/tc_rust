//! Noekeon ECB vectors from Bouncy Castle's `NoekeonTest.cs`.

mod common;

use common::unhex;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_noekeon_v2::{BLOCK_BYTES, NoekeonEngine};

fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = KeyRef::new(&key);
    let mut engine = NoekeonEngine::new();

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
fn all_bouncy_castle_vectors_match_in_both_directions() {
    for (key, plaintext, ciphertext) in [
        (
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "b1656851699e29fa24b70148503d2dfc",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffff",
            "2a78421b87c7d0924f26113f1d1349b2",
        ),
        (
            "b1656851699e29fa24b70148503d2dfc",
            "2a78421b87c7d0924f26113f1d1349b2",
            "e2f687e07b75660ffc372233bc47532c",
        ),
    ] {
        run_vector(key, plaintext, ciphertext);
    }
}
