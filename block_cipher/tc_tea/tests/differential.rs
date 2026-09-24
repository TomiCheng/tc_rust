//! XTEA agrees with RustCrypto after an explicit per-word endianness conversion.

mod common;

use common::unhex;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_tea_v2::{BLOCK_BYTES, KEY_BYTES, XteaEngine};
use xtea::Xtea;
use xtea::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

// RustCrypto reads and writes little-endian u32 words; this crate uses big-endian.
fn reverse_words(bytes: &mut [u8]) {
    for word in bytes.chunks_exact_mut(4) {
        word.reverse();
    }
}

fn reference_block(key: &[u8], input: &[u8], direction: CipherDirection) -> Vec<u8> {
    let mut key = key.to_vec();
    reverse_words(&mut key);
    let reference = Xtea::new_from_slice(&key).unwrap();
    let mut block = Block::<Xtea>::try_from(input).unwrap();
    reverse_words(&mut block);
    match direction {
        CipherDirection::Encrypt => reference.encrypt_block(&mut block),
        CipherDirection::Decrypt => reference.decrypt_block(&mut block),
    }
    reverse_words(&mut block);
    block.to_vec()
}

#[test]
fn xtea_matches_rustcrypto_after_word_conversion_on_a_known_answer_and_64_random_pairs() {
    let key = unhex("0123456712345678234567893456789A");
    let plaintext = unhex("0102030405060708");
    let ciphertext = unhex("8c67155b2ef91ead");
    assert_eq!(
        reference_block(&key, &plaintext, CipherDirection::Encrypt),
        ciphertext
    );
    assert_eq!(
        reference_block(&key, &ciphertext, CipherDirection::Decrypt),
        plaintext
    );

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed as u8
    };
    for _ in 0..64 {
        let key: [u8; KEY_BYTES] = core::array::from_fn(|_| next());
        let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
        for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
            let expected = reference_block(&key, &input, direction);
            let mut engine = XteaEngine::new();
            engine.init(direction, &KeyRef::new(&key)).unwrap();
            let mut actual = [0; BLOCK_BYTES];
            engine.process_block(&input, &mut actual).unwrap();
            assert_eq!(actual.as_slice(), expected, "{direction:?}");
        }
    }
}
