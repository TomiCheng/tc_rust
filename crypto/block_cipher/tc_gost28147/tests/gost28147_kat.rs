//! GOST 28147 vectors from Bouncy Castle's `GOST28147Test.cs`.

mod common;

use common::unhex;
use tc_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_gost28147::{BLOCK_BYTES, Gost28147Engine, KeyWithSBox, s_box};
use tc_params::{KeyParams, SBoxParams};

/// The key every Bouncy Castle vector below uses.
const KEY: &str = "546d203368656c326973652073736e62206167796967747473656865202c3d73";

fn encrypt_block<P: KeyParams + SBoxParams + ?Sized>(
    params: &P,
    input: &[u8],
) -> [u8; BLOCK_BYTES] {
    let mut engine = Gost28147Engine::new();
    engine.init(CipherDirection::Encrypt, params).unwrap();
    let mut output = [0u8; BLOCK_BYTES];
    assert_eq!(
        engine.process_block(input, &mut output).unwrap(),
        BLOCK_BYTES
    );
    output
}

fn assert_block_vector<P: KeyParams + SBoxParams + ?Sized>(
    params: &P,
    plaintext: &str,
    ciphertext: &str,
) {
    let plaintext = unhex(plaintext);
    let ciphertext = unhex(ciphertext);
    assert_eq!(encrypt_block(params, &plaintext).as_slice(), ciphertext);

    let mut engine = Gost28147Engine::new();
    engine.init(CipherDirection::Decrypt, params).unwrap();
    let mut recovered = [0u8; BLOCK_BYTES];
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

/// Bouncy Castle publishes some vectors through CFB-8 rather than as raw
/// blocks, so the mode is inlined here until a modes crate exists.
fn cfb8_encrypt<P: KeyParams + SBoxParams + ?Sized>(
    params: &P,
    iv: &[u8; BLOCK_BYTES],
    input: &[u8],
) -> Vec<u8> {
    let mut engine = Gost28147Engine::new();
    engine.init(CipherDirection::Encrypt, params).unwrap();

    let mut feedback = *iv;
    let mut output = Vec::with_capacity(input.len());
    for &byte in input {
        let mut gamma = [0u8; BLOCK_BYTES];
        engine.process_block(&feedback, &mut gamma).unwrap();
        let encrypted = byte ^ gamma[0];
        feedback.copy_within(1.., 0);
        feedback[BLOCK_BYTES - 1] = encrypted;
        output.push(encrypted);
    }
    output
}

#[test]
fn bc_default_s_box_block_vector() {
    let key = unhex(KEY);
    assert_block_vector(
        &KeyWithSBox::new(&key),
        "0000000000000000",
        "1b0bbc32cebcab42",
    );
}

#[test]
fn bc_named_s_box_block_vectors() {
    let key = unhex(KEY);
    for (table, expected) in [
        (s_box::D_TEST, "b587f7a0814c911d"),
        (s_box::E_TEST, "e8287f53f991d52b"),
        (s_box::E_A, "c41009dba22ebe35"),
    ] {
        assert_block_vector(
            &KeyWithSBox::with_s_box(&key, &table),
            "1234567890abcdef",
            expected,
        );
    }
}

#[test]
fn bc_named_s_box_cfb8_vectors() {
    let key = unhex(KEY);
    let iv: [u8; BLOCK_BYTES] = unhex("1234567890abcdef").try_into().unwrap();
    for (table, expected) in [
        (s_box::E_B, "80d8723fcd3aba28"),
        (s_box::E_C, "739f6f95068499b5"),
        (s_box::E_D, "4663f720f4340f57"),
        (s_box::D_A, "5bb0a31d218ed564"),
    ] {
        let params = KeyWithSBox::with_s_box(&key, &table);
        assert_eq!(cfb8_encrypt(&params, &iv, &[0u8; 8]), unhex(expected));
    }
}

#[test]
fn bc_custom_s_box_vector() {
    let key = unhex(KEY);
    let iv: [u8; BLOCK_BYTES] = unhex("1234567890abcdef").try_into().unwrap();

    // 交替遞增與遞減的列;不是標準表,但每列仍是排列。
    let mut table = [0u8; s_box::BYTES];
    for (row, entries) in table.chunks_exact_mut(s_box::COLUMNS).enumerate() {
        for (column, value) in entries.iter_mut().enumerate() {
            *value = if row % 2 == 0 {
                column as u8
            } else {
                15 - column as u8
            };
        }
    }

    let params = KeyWithSBox::with_s_box(&key, &table);
    assert_eq!(
        cfb8_encrypt(&params, &iv, &[0u8; 8]),
        unhex("c3af96ef788667c5")
    );
}
