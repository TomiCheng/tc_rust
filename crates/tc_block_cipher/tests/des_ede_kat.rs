//! Triple DES vectors from Bouncy Castle's `DESedeTest.cs` and NIST examples.

use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_block_cipher::{DES_EDE_BLOCK_BYTES, DesEdeEngine, DesEdeParams};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn run_vector(key: &str, plaintext: &str, ciphertext: &str) {
    let key = unhex(key);
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let params = DesEdeParams::new(&key).unwrap();
    let mut engine = DesEdeEngine::new();
    let mut encrypted = vec![0u8; plaintext.len()];

    engine.init(CipherDirection::Encrypt, &params).unwrap();
    for (input, output) in plaintext
        .chunks_exact(DES_EDE_BLOCK_BYTES)
        .zip(encrypted.chunks_exact_mut(DES_EDE_BLOCK_BYTES))
    {
        engine.process_block(input, output).unwrap();
    }
    assert_eq!(encrypted, ciphertext);

    let mut recovered = vec![0u8; ciphertext.len()];
    engine.init(CipherDirection::Decrypt, &params).unwrap();
    for (input, output) in ciphertext
        .chunks_exact(DES_EDE_BLOCK_BYTES)
        .zip(recovered.chunks_exact_mut(DES_EDE_BLOCK_BYTES))
    {
        engine.process_block(input, output).unwrap();
    }
    assert_eq!(recovered, plaintext);
}

#[test]
fn bc_two_key_and_three_key_vectors() {
    const PLAINTEXT: &str = "4e6f77206973207468652074696d6520666f7220616c6c20";
    const SINGLE_DES_RESULT: &str = "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53";
    const TWO_KEY_RESULT: &str = "d80a0d8b2bae5e4e6a0094171abcfc2775d2235a706e232c";

    run_vector(
        "0123456789abcdef0123456789abcdef",
        PLAINTEXT,
        SINGLE_DES_RESULT,
    );
    run_vector(
        "0123456789abcdeffedcba9876543210",
        PLAINTEXT,
        TWO_KEY_RESULT,
    );
    run_vector(
        "0123456789abcdef0123456789abcdef0123456789abcdef",
        PLAINTEXT,
        SINGLE_DES_RESULT,
    );
    run_vector(
        "0123456789abcdeffedcba98765432100123456789abcdef",
        PLAINTEXT,
        TWO_KEY_RESULT,
    );
}

#[test]
fn nist_three_distinct_component_keys_vector() {
    run_vector(
        "0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123",
        "FEDCBA9876543210",
        "0737F6C53750D4A4",
    );
}
