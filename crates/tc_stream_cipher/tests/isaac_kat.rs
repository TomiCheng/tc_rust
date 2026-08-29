//! Known-answer and behavioral tests for the ISAAC stream cipher.
//!
//! The known-answer values are copied from Bouncy Castle's `IsaacTest`, which
//! cites Bob Jenkins' ISAAC reference material.

use tc_cipher_core::{StreamCipher, StreamCipherInit};
use tc_stream_cipher::{ISAAC_MAX_KEY_BYTES, IsaacEngine, IsaacParams, StreamCipherError};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn keystream(key: &[u8], length: usize) -> Vec<u8> {
    let params = IsaacParams::new(key).unwrap();
    let mut engine = IsaacEngine::new();
    engine.init(&params).unwrap();
    let mut output = vec![0u8; length];
    assert_eq!(
        engine.process_bytes(&vec![0u8; length], &mut output),
        Ok(length)
    );
    output
}

#[test]
fn bc_zero_word_key_vector() {
    let expected = hex("f650e4c8e448e96d98db2fb4f5fad54f\
         433f1afbedec154ad837048746ca4f9a\
         5de3743e88381097f1d444eb823cedb6\
         6a83e1e04a5f6355c744243325890e2e");
    assert_eq!(keystream(&[0u8; 4], expected.len()), expected);
}

#[test]
fn bc_all_ones_word_key_vector() {
    let expected = hex("de3b3f3c19e0629c1fc8b7836695d523\
         e7804edd86ff7ce9b106f52caebae9d9\
         72f845d49ce17d7da44e49bae954aac0\
         d0b1284b98a88eec1524fb6bc91a16b5");
    assert_eq!(keystream(&[0xffu8; 4], expected.len()), expected);
}

#[test]
fn bc_full_state_repeating_ffff0000_vector() {
    let mut key = [0u8; ISAAC_MAX_KEY_BYTES];
    for word in key.chunks_exact_mut(4) {
        word[..2].fill(0xff);
    }
    let expected = hex("26c54b1f8c4e3fc582e9e8180f7aba53\
         80463dcf58b03cbeda0ecc8ba90ccff8\
         5bd50896313d7efed44015faeac6964b\
         241a7fb8a2e37127a7cbea0fd7c020f2");
    assert_eq!(keystream(&key, expected.len()), expected);
}

#[test]
fn bc_full_state_repeating_0000ffff_vector() {
    let mut key = [0u8; ISAAC_MAX_KEY_BYTES];
    for word in key.chunks_exact_mut(4) {
        word[2..].fill(0xff);
    }
    let expected = hex("bc31712f2a2f467a5abc737c57ce0f8d\
         49d2f775eb850fc8f856daf19310fee2\
         5bab40e78403c9ef4ccd971418992faf\
         4e85ca643fa6b482f30c4659066158a6");
    assert_eq!(keystream(&key, expected.len()), expected);
}

#[test]
fn empty_key_matches_bc_zero_word_state() {
    assert_eq!(keystream(&[], 64), keystream(&[0u8; 4], 64));
}

#[test]
fn reset_chunking_and_single_byte_processing_match() {
    let params = IsaacParams::new(b"ISAAC test key").unwrap();
    let input = vec![0x5au8; 1_077];

    let mut engine = IsaacEngine::new();
    assert_eq!(engine.algorithm_name(), "ISAAC");
    engine.init(&params).unwrap();
    let mut bulk = vec![0u8; input.len()];
    engine.process_bytes(&input, &mut bulk).unwrap();

    engine.reset();
    let mut chunked = vec![0u8; input.len()];
    engine
        .process_bytes(&input[..13], &mut chunked[..13])
        .unwrap();
    engine
        .process_bytes(&input[13..1023], &mut chunked[13..1023])
        .unwrap();
    engine
        .process_bytes(&input[1023..], &mut chunked[1023..])
        .unwrap();
    assert_eq!(chunked, bulk);

    engine.reset();
    let single: Vec<u8> = input
        .iter()
        .map(|&byte| engine.return_byte(byte).unwrap())
        .collect();
    assert_eq!(single, bulk);
}

#[test]
fn encrypt_decrypt_round_trips() {
    let params = IsaacParams::new(b"symmetric key").unwrap();
    let plaintext = b"ISAAC encryption and decryption use the same operation";
    let mut engine = IsaacEngine::new();

    engine.init(&params).unwrap();
    let mut ciphertext = vec![0u8; plaintext.len()];
    engine.process_bytes(plaintext, &mut ciphertext).unwrap();

    engine.init(&params).unwrap();
    let mut recovered = vec![0u8; plaintext.len()];
    engine.process_bytes(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn validates_parameters_and_runtime_state() {
    assert_eq!(
        IsaacParams::new(&[0u8; ISAAC_MAX_KEY_BYTES + 1]).unwrap_err(),
        StreamCipherError::InvalidKeyLength(ISAAC_MAX_KEY_BYTES + 1)
    );

    let params = IsaacParams::new(b"secret material").unwrap();
    let debug = format!("{params:?}");
    assert!(debug.contains("key_len"));
    assert!(!debug.contains("secret material"));

    let mut engine = IsaacEngine::new();
    assert_eq!(
        engine.return_byte(0),
        Err(StreamCipherError::NotInitialised)
    );
    assert_eq!(
        engine.process_bytes(&[0u8; 2], &mut [0u8; 2]),
        Err(StreamCipherError::NotInitialised)
    );

    engine.init(&params).unwrap();
    assert_eq!(
        engine.process_bytes(&[0u8; 2], &mut [0u8; 1]),
        Err(StreamCipherError::OutputBufferTooShort)
    );
}
