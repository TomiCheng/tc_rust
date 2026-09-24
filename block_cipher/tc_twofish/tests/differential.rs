//! Twofish agrees with RustCrypto after establishing the KAT byte order.

mod common;

use common::unhex;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_twofish_v2::{BLOCK_BYTES, KEY_BYTES, TwofishEngine};
use twofish::Twofish;
use twofish::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

#[test]
fn twofish_matches_rustcrypto_on_the_known_vector_and_64_key_block_pairs() {
    let key = unhex("000102030405060708090a0b0c0d0e0f");
    let plaintext = unhex("000102030405060708090a0b0c0d0e0f");
    let ciphertext = unhex("9fb63337151be9c71306d159ea7afaa4");
    let reference = Twofish::new_from_slice(&key).unwrap();
    let mut block = Block::<Twofish>::try_from(plaintext.as_slice()).unwrap();
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
    for size in KEY_BYTES {
        for _ in 0..64 {
            let key: Vec<u8> = (0..size).map(|_| next()).collect();
            let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
            let reference = Twofish::new_from_slice(&key).unwrap();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<Twofish>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = TwofishEngine::new();
                engine.init(direction, &KeyRef::new(&key)).unwrap();
                let mut actual = [0; BLOCK_BYTES];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
            }
        }
    }
}
