//! Both Camellia engines agree with RustCrypto and each other.

mod common;

use camellia::cipher::{
    Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit, consts::U16,
};
use camellia::{Camellia128, Camellia192, Camellia256};
use common::unhex;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_camellia_v2::{BLOCK_BYTES, CamelliaEngine, CamelliaLightEngine};

fn check<C>(key_hex: &str, ciphertext_hex: &str)
where
    C: KeyInit + BlockCipherEncrypt + BlockCipherDecrypt + BlockSizeUser<BlockSize = U16>,
{
    let key = unhex(key_hex);
    let plaintext = unhex("0123456789abcdeffedcba9876543210");
    let ciphertext = unhex(ciphertext_hex);
    let reference = C::new_from_slice(&key).unwrap();
    let mut block = Block::<C>::try_from(plaintext.as_slice()).unwrap();
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
        let key: Vec<u8> = (0..key.len()).map(|_| next()).collect();
        let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
        let reference = C::new_from_slice(&key).unwrap();
        for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
            let mut expected = Block::<C>::from(input);
            match direction {
                CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
            }
            let mut standard = CamelliaEngine::new();
            let mut light = CamelliaLightEngine::new();
            standard.init(direction, &KeyRef::new(&key)).unwrap();
            light.init(direction, &KeyRef::new(&key)).unwrap();
            let mut actual = [0; BLOCK_BYTES];
            let mut compact = [0; BLOCK_BYTES];
            standard.process_block(&input, &mut actual).unwrap();
            light.process_block(&input, &mut compact).unwrap();
            assert_eq!(actual, compact);
            assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
        }
    }
}

#[test]
fn both_camellia_engines_match_rustcrypto_on_each_key_sizes_kat_and_64_random_pairs() {
    check::<Camellia128>(
        "0123456789abcdeffedcba9876543210",
        "67673138549669730857065648eabe43",
    );
    check::<Camellia192>(
        "0123456789abcdeffedcba98765432100011223344556677",
        "b4993401b3e996f84ee5cee7d79b09b9",
    );
    check::<Camellia256>(
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "9acc237dff16d76c20ef7c919e3a7509",
    );
}
