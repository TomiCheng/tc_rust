//! Known-answer tests for the RC4 stream cipher.
//!
//! Uses the classic ASCII test vectors and the RFC 6229 keystream vectors
//! (RFC 6229 gives the keystream as the encryption of all-zero input). Also
//! checks reset, `return_byte`/`process_bytes` consistency, and error paths.

use tc_crypto_core::StreamCipher;
use tc_stream_cipher::{Rc4Engine, Rc4Error, Rc4Params};

/// Parses a hex string into bytes.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn encrypt(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut engine = Rc4Engine::new();
    engine.init(true, &Rc4Params::new(key).unwrap()).unwrap();
    let mut out = vec![0u8; input.len()];
    let n = engine.process_bytes(input, &mut out).unwrap();
    assert_eq!(n, input.len());
    out
}

#[test]
fn classic_key_plaintext() {
    assert_eq!(encrypt(b"Key", b"Plaintext"), hex("BBF316E8D940AF0AD3"));
}

#[test]
fn classic_wiki_pedia() {
    assert_eq!(encrypt(b"Wiki", b"pedia"), hex("1021BF0420"));
}

#[test]
fn classic_secret_attack() {
    assert_eq!(
        encrypt(b"Secret", b"Attack at dawn"),
        hex("45A01F645FC35B383552544B9BF5")
    );
}

#[test]
fn rfc6229_40bit_key() {
    // keystream = 加密 32 個零位元組。
    let ks = encrypt(&hex("0102030405"), &[0u8; 32]);
    assert_eq!(
        ks,
        hex("B2396305F03DC027CCC3524A0A1118A86982944F18FC82D589C403A47A0D0919")
    );
}

#[test]
fn rfc6229_128bit_key() {
    let ks = encrypt(&hex("0102030405060708090A0B0C0D0E0F10"), &[0u8; 16]);
    assert_eq!(ks, hex("9AC7CC9A609D1EF7B2932899CDE41B97"));
}

#[test]
fn decrypt_round_trips() {
    // RC4 對稱：對密文再跑一次即還原。
    let key = b"Secret";
    let plaintext = b"Attack at dawn";
    let ct = encrypt(key, plaintext);
    let pt = encrypt(key, &ct);
    assert_eq!(pt, plaintext);
}

#[test]
fn reset_restarts_keystream() {
    let mut engine = Rc4Engine::new();
    engine.init(true, &Rc4Params::new(b"Key").unwrap()).unwrap();

    let mut first = [0u8; 9];
    engine.process_bytes(b"Plaintext", &mut first).unwrap();

    engine.reset();
    let mut second = [0u8; 9];
    engine.process_bytes(b"Plaintext", &mut second).unwrap();

    assert_eq!(first, second);
}

#[test]
fn return_byte_matches_process_bytes() {
    let key = Rc4Params::new(b"Key").unwrap();
    let input = b"Plaintext and more";

    let mut bulk = Rc4Engine::new();
    bulk.init(true, &key).unwrap();
    let mut bulk_out = vec![0u8; input.len()];
    bulk.process_bytes(input, &mut bulk_out).unwrap();

    let mut single = Rc4Engine::new();
    single.init(true, &key).unwrap();
    let byte_out: Vec<u8> = input
        .iter()
        .map(|&b| single.return_byte(b).unwrap())
        .collect();

    assert_eq!(bulk_out, byte_out);
}

#[test]
fn errors_before_init_and_on_short_output() {
    let mut engine = Rc4Engine::new();
    // 尚未 init。
    assert_eq!(engine.return_byte(0), Err(Rc4Error::NotInitialised));
    let mut out = [0u8; 4];
    assert_eq!(
        engine.process_bytes(b"data", &mut out),
        Err(Rc4Error::NotInitialised)
    );

    // 輸出緩衝太短。
    engine.init(true, &Rc4Params::new(b"Key").unwrap()).unwrap();
    let mut short = [0u8; 2];
    assert_eq!(
        engine.process_bytes(b"data", &mut short),
        Err(Rc4Error::OutputBufferTooShort)
    );

    // 無效金鑰長度。
    assert_eq!(
        Rc4Params::new(&[]).unwrap_err(),
        Rc4Error::InvalidKeyLength(0)
    );
}
