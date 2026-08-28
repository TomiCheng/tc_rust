//! IDEA ECB vectors from Bouncy Castle's `IDEATest.cs`.

use tc_crypto_core::BlockCipher;
use tc_crypto_engines::{IdeaEngine, IdeaParams};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

/// Runs each 8-byte block of the vector through ECB in both directions.
fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = IdeaParams::new(&key).unwrap();

    let mut engine = IdeaEngine::new();
    engine.init(true, &params).unwrap();
    let mut encrypted = vec![0u8; plaintext.len()];
    for (pt, ct) in plaintext.chunks_exact(8).zip(encrypted.chunks_exact_mut(8)) {
        assert_eq!(engine.process_block(pt, ct).unwrap(), 8);
    }
    assert_eq!(encrypted, ciphertext);

    engine.init(false, &params).unwrap();
    let mut decrypted = vec![0u8; ciphertext.len()];
    for (ct, pt) in ciphertext.chunks_exact(8).zip(decrypted.chunks_exact_mut(8)) {
        engine.process_block(ct, pt).unwrap();
    }
    assert_eq!(decrypted, plaintext);
}

#[test]
fn bc_ecb_vectors() {
    run_vector(
        "00112233445566778899AABBCCDDEEFF",
        "000102030405060708090a0b0c0d0e0f",
        "ed732271a7b39f475b4b2b6719f194bf",
    );
    run_vector(
        "00112233445566778899AABBCCDDEEFF",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "b8bc6ed5c899265d2bcfad1fc6d4287d",
    );
}
