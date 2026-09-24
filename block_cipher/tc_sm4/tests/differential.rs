//! SM4 agrees with RustCrypto after establishing the KAT byte order.

mod common;

use common::unhex;
use sm4::Sm4;
use sm4::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_sm4_v2::{BLOCK_BYTES, KEY_BYTES, Sm4Engine};

#[test]
fn sm4_matches_rustcrypto_on_the_known_vector_and_64_key_block_pairs() {
    let key = unhex("0123456789abcdeffedcba9876543210");
    let plaintext = unhex("0123456789abcdeffedcba9876543210");
    let ciphertext = unhex("681edf34d206965e86b3e94f536e4246");
    let reference = Sm4::new_from_slice(&key).unwrap();
    let mut block = Block::<Sm4>::try_from(plaintext.as_slice()).unwrap();
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
    for _ in 0..64 {
        let key: [u8; KEY_BYTES] = core::array::from_fn(|_| next());
        let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
        let reference = Sm4::new_from_slice(&key).unwrap();
        for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
            let mut expected = Block::<Sm4>::from(input);
            match direction {
                CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
            }
            let mut engine = Sm4Engine::new();
            engine.init(direction, &KeyRef::new(&key)).unwrap();
            let mut actual = [0; BLOCK_BYTES];
            engine.process_block(&input, &mut actual).unwrap();
            assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
        }
    }
}
