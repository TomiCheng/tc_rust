//! IDEA ECB vectors from Bouncy Castle's `IDEATest.cs` and the reference
//! implementation published with the algorithm.

mod common;

use common::{Key, unhex};
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_idea::{BLOCK_BYTES, IdeaEngine};

/// Runs every block of the vector through ECB in both directions.
fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = Key(&key);
    let mut engine = IdeaEngine::new();

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let mut encrypted = vec![0u8; plaintext.len()];
    for (input, output) in plaintext
        .chunks_exact(BLOCK_BYTES)
        .zip(encrypted.chunks_exact_mut(BLOCK_BYTES))
    {
        assert_eq!(engine.process_block(input, output).unwrap(), BLOCK_BYTES);
    }
    assert_eq!(encrypted, ciphertext);

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = vec![0u8; ciphertext.len()];
    for (input, output) in ciphertext
        .chunks_exact(BLOCK_BYTES)
        .zip(recovered.chunks_exact_mut(BLOCK_BYTES))
    {
        engine.process_block(input, output).unwrap();
    }
    assert_eq!(recovered, plaintext);
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

#[test]
fn reference_single_block_vector() {
    run_vector(
        "00010002000300040005000600070008",
        "0000000100020003",
        "11FBED2B01986DE5",
    );
}
