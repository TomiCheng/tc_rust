//! Blowfish vectors from Bouncy Castle's `BlowfishTest.cs`.

use tc_crypto_core::BlockCipher;
use tc_crypto_engines::{BLOWFISH_BLOCK_BYTES, BlowfishEngine, BlowfishParams};

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
    let params = BlowfishParams::new(&key).unwrap();
    let mut engine = BlowfishEngine::new();

    engine.init(true, &params).unwrap();
    let mut encrypted = [0u8; BLOWFISH_BLOCK_BYTES];
    assert_eq!(
        engine.process_block(&plaintext, &mut encrypted).unwrap(),
        BLOWFISH_BLOCK_BYTES
    );
    assert_eq!(encrypted.as_slice(), ciphertext);

    engine.init(false, &params).unwrap();
    let mut recovered = [0u8; BLOWFISH_BLOCK_BYTES];
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn bc_vectors() {
    for (key, plaintext, ciphertext) in [
        ("0000000000000000", "0000000000000000", "4EF997456198DD78"),
        ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"),
        ("3000000000000000", "1000000000000001", "7D856F9A613063F2"),
        ("1111111111111111", "1111111111111111", "2466DD878B963C9D"),
        ("0123456789ABCDEF", "1111111111111111", "61F9C3802281B096"),
        ("FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D"),
        ("7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B"),
        ("0131D9619DC1376E", "5CD54CA83DEF57DA", "B1B8CC0B250F09A0"),
    ] {
        run_vector(key, plaintext, ciphertext);
    }
}

#[test]
fn maximum_length_key_round_trips() {
    let key: Vec<u8> = (0..56).map(|value| value as u8).collect();
    let params = BlowfishParams::new(&key).unwrap();
    let plaintext = [0xA5; BLOWFISH_BLOCK_BYTES];
    let mut ciphertext = [0u8; BLOWFISH_BLOCK_BYTES];
    let mut recovered = [0u8; BLOWFISH_BLOCK_BYTES];
    let mut engine = BlowfishEngine::new();

    engine.init(true, &params).unwrap();
    engine.process_block(&plaintext, &mut ciphertext).unwrap();
    engine.init(false, &params).unwrap();
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered, plaintext);
}
