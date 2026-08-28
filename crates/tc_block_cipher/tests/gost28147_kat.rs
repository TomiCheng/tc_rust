//! GOST 28147 vectors from Bouncy Castle's `GOST28147Test.cs`.

use tc_crypto_core::BlockCipher;
use tc_block_cipher::{GOST28147_BLOCK_BYTES, Gost28147Engine, Gost28147Params, Gost28147SBox};

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

fn encrypt_block(params: &Gost28147Params, input: &[u8]) -> [u8; GOST28147_BLOCK_BYTES] {
    let mut engine = Gost28147Engine::new();
    engine.init(true, params).unwrap();
    let mut output = [0u8; GOST28147_BLOCK_BYTES];
    assert_eq!(engine.process_block(input, &mut output).unwrap(), 8);
    output
}

fn assert_block_vector(params: &Gost28147Params, plaintext: &str, ciphertext: &str) {
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    let encrypted = encrypt_block(params, &plaintext);
    assert_eq!(encrypted.as_slice(), ciphertext);

    let mut engine = Gost28147Engine::new();
    engine.init(false, params).unwrap();
    let mut recovered = [0u8; GOST28147_BLOCK_BYTES];
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

fn cfb8_encrypt(
    params: &Gost28147Params,
    iv: &[u8; GOST28147_BLOCK_BYTES],
    input: &[u8],
) -> Vec<u8> {
    let mut engine = Gost28147Engine::new();
    engine.init(true, params).unwrap();
    let mut feedback = *iv;
    let mut output = Vec::with_capacity(input.len());

    for &byte in input {
        let mut gamma = [0u8; GOST28147_BLOCK_BYTES];
        engine.process_block(&feedback, &mut gamma).unwrap();
        let encrypted = byte ^ gamma[0];
        feedback.copy_within(1.., 0);
        feedback[GOST28147_BLOCK_BYTES - 1] = encrypted;
        output.push(encrypted);
    }
    output
}

#[test]
fn bc_default_s_box_block_vector() {
    let key = unhex("546d203368656c326973652073736e62206167796967747473656865202c3d73");
    let params = Gost28147Params::new(&key).unwrap();
    assert_block_vector(&params, "0000000000000000", "1b0bbc32cebcab42");
}

#[test]
fn bc_named_s_box_vectors() {
    let key = unhex("546d203368656c326973652073736e62206167796967747473656865202c3d73");
    let iv = "1234567890abcdef";

    for (s_box, expected) in [
        (Gost28147SBox::DigestTest, "b587f7a0814c911d"),
        (Gost28147SBox::EncryptionTest, "e8287f53f991d52b"),
        (Gost28147SBox::EncryptionA, "c41009dba22ebe35"),
    ] {
        let params = Gost28147Params::with_s_box(&key, s_box).unwrap();
        assert_block_vector(&params, iv, expected);
    }

    let iv: [u8; 8] = unhex(iv).try_into().unwrap();
    for (s_box, expected) in [
        (Gost28147SBox::EncryptionB, "80d8723fcd3aba28"),
        (Gost28147SBox::EncryptionC, "739f6f95068499b5"),
        (Gost28147SBox::EncryptionD, "4663f720f4340f57"),
        (Gost28147SBox::DigestA, "5bb0a31d218ed564"),
    ] {
        let params = Gost28147Params::with_s_box(&key, s_box).unwrap();
        assert_eq!(cfb8_encrypt(&params, &iv, &[0u8; 8]), unhex(expected));
    }
}

#[test]
fn bc_custom_s_box_vector() {
    let key = unhex("546d203368656c326973652073736e62206167796967747473656865202c3d73");
    let iv: [u8; 8] = unhex("1234567890abcdef").try_into().unwrap();
    let mut s_box = [0u8; 128];
    for (row_index, row) in s_box.chunks_exact_mut(16).enumerate() {
        for (column, value) in row.iter_mut().enumerate() {
            *value = if row_index % 2 == 0 {
                column as u8
            } else {
                15 - column as u8
            };
        }
    }

    let params = Gost28147Params::with_custom_s_box(&key, &s_box).unwrap();
    assert_eq!(
        cfb8_encrypt(&params, &iv, &[0u8; 8]),
        unhex("c3af96ef788667c5")
    );
}

#[test]
fn every_named_s_box_round_trips() {
    let key = [0xA5u8; 32];
    let plaintext = [0x3Cu8; 8];
    for s_box in [
        Gost28147SBox::Default,
        Gost28147SBox::EncryptionTest,
        Gost28147SBox::EncryptionA,
        Gost28147SBox::EncryptionB,
        Gost28147SBox::EncryptionC,
        Gost28147SBox::EncryptionD,
        Gost28147SBox::DigestTest,
        Gost28147SBox::DigestA,
    ] {
        let params = Gost28147Params::with_s_box(&key, s_box).unwrap();
        let encrypted = encrypt_block(&params, &plaintext);
        let mut engine = Gost28147Engine::new();
        engine.init(false, &params).unwrap();
        let mut recovered = [0u8; 8];
        engine.process_block(&encrypted, &mut recovered).unwrap();
        assert_eq!(recovered, plaintext, "{}", s_box.name());
    }
}
