//! Blowfish agrees with RustCrypto after establishing the KAT byte order.

mod common;

use blowfish::Blowfish;
use blowfish::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use common::unhex;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_blowfish_v2::{BLOCK_BYTES, BlowfishEngine, MAX_KEY_BYTES, MIN_KEY_BYTES};

#[test]
fn blowfish_matches_rustcrypto_on_the_known_vector_and_64_key_block_pairs() {
    let key = unhex("0000000000000000");
    let plaintext = unhex("0000000000000000");
    let ciphertext = unhex("4EF997456198DD78");
    let reference: Blowfish = Blowfish::new_from_slice(&key).unwrap();
    let mut block = Block::<Blowfish>::try_from(plaintext.as_slice()).unwrap();
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
    for size in MIN_KEY_BYTES..=MAX_KEY_BYTES {
        for _ in 0..64 {
            let key: Vec<u8> = (0..size).map(|_| next()).collect();
            let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
            let reference: Blowfish = Blowfish::new_from_slice(&key).unwrap();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<Blowfish>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = BlowfishEngine::new();
                engine.init(direction, &KeyRef::new(&key)).unwrap();
                let mut actual = [0; BLOCK_BYTES];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
            }
        }
    }
}
