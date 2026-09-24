//! Serpent agrees with RustCrypto after establishing the KAT byte order.

mod common;

use common::unhex;
use serpent::Serpent;
use serpent::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_serpent_v2::{BLOCK_BYTES, KEY_STEP_BYTES, MAX_KEY_BYTES, SerpentEngine};

#[test]
fn serpent_matches_rustcrypto_on_the_known_vector_and_64_key_block_pairs() {
    let key = unhex("00000000000000000000000000000000");
    let plaintext = unhex("00000000000000000000000000000000");
    let ciphertext = unhex("3620b17ae6a993d09618b8768266bae9");
    let reference = Serpent::new_from_slice(&key).unwrap();
    let mut block = Block::<Serpent>::try_from(plaintext.as_slice()).unwrap();
    reference.encrypt_block(&mut block);
    assert_eq!(block.as_slice(), ciphertext);
    reference.decrypt_block(&mut block);
    assert_eq!(block.as_slice(), plaintext);

    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed as u8
    };
    // RustCrypto rejects keys shorter than 16 bytes; do not invent a mapping.
    for size in (16..=MAX_KEY_BYTES).step_by(KEY_STEP_BYTES) {
        for _ in 0..64 {
            let key: Vec<u8> = (0..size).map(|_| next()).collect();
            let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
            let reference = Serpent::new_from_slice(&key).unwrap();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<Serpent>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = SerpentEngine::new();
                engine.init(direction, &KeyRef::new(&key)).unwrap();
                let mut actual = [0; BLOCK_BYTES];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
            }
        }
    }
}
