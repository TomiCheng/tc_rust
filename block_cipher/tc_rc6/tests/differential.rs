//! RC6-32/20 agrees with RustCrypto's published 16-byte-key alias.

mod common;

use common::unhex;
use rc6::RC6_32_20_16;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_rc6_v2::{BLOCK_BYTES, Rc6Engine};

fn reference_block(key: &[u8; 16], input: [u8; 16], direction: CipherDirection) -> [u8; 16] {
    let reference = RC6_32_20_16::new(&(*key).into());
    let mut block = input.into();
    match direction {
        CipherDirection::Encrypt => reference.encrypt(From::from(&mut block)),
        CipherDirection::Decrypt => reference.decrypt(From::from(&mut block)),
    }
    block.into()
}

#[test]
fn rc6_matches_rustcrypto_on_the_known_vector_and_64_128_bit_key_block_pairs() {
    let key = [0; 16];
    let plaintext: [u8; BLOCK_BYTES] = unhex("80000000000000000000000000000000")
        .try_into()
        .unwrap();
    let ciphertext: [u8; BLOCK_BYTES] = unhex("f71f65e7b80c0c6966fee607984b5cdf")
        .try_into()
        .unwrap();
    assert_eq!(
        reference_block(&key, plaintext, CipherDirection::Encrypt),
        ciphertext
    );
    assert_eq!(
        reference_block(&key, ciphertext, CipherDirection::Decrypt),
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
        let key: [u8; 16] = core::array::from_fn(|_| next());
        let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
        for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
            let expected = reference_block(&key, input, direction);
            let mut engine = Rc6Engine::new();
            engine.init(direction, &KeyRef::new(&key)).unwrap();
            let mut actual = [0; BLOCK_BYTES];
            engine.process_block(&input, &mut actual).unwrap();
            assert_eq!(actual, expected, "{direction:?}");
        }
    }
}
