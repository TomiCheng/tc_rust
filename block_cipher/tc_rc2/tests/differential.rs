//! SM4 agrees with RustCrypto after establishing the KAT byte order.

mod common;

use common::unhex;
use rc2::Rc2;
use rc2::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_rc2_v2::{BLOCK_BYTES, MAX_KEY_BYTES, Params, Rc2Engine};

#[test]
fn rc2_matches_rustcrypto_on_the_known_vector_and_64_key_block_pairs() {
    let key = unhex("0000000000000000");
    let plaintext = unhex("0000000000000000");
    let ciphertext = unhex("ebb773f993278eff");
    let reference = Rc2::new_with_eff_key_len(&key, 63);
    let mut block = Block::<Rc2>::try_from(plaintext.as_slice()).unwrap();
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
    for size in 1..=MAX_KEY_BYTES {
        for index in 0..64 {
            let key: Vec<u8> = (0..size).map(|_| next()).collect();
            let bits = [1, 7, 8, 63, 64, 129, size * 8, 1024][index % 8];
            let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
            let reference = Rc2::new_with_eff_key_len(&key, bits);
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<Rc2>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = Rc2Engine::new();
                engine
                    .init(direction, &Params::with_effective_key_bits(&key, bits))
                    .unwrap();
                let mut actual = [0; BLOCK_BYTES];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
            }
        }
    }
}
