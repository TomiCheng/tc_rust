//! Threefish with a nonzero tweak agrees with RustCrypto for all block widths.

mod common;

use common::unhex;
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_threefish_v2::{Params, ThreefishEngine};
use threefish::{Threefish256, Threefish512, Threefish1024};

macro_rules! compare {
    ($name:ident, $reference:ty, $words:literal, $ciphertext:expr) => {
        #[test]
        fn $name() {
            const SIZE: usize = $words * 8;
            let key: [u8; SIZE] = core::array::from_fn(|i| 0x10 + i as u8);
            let tweak: [u8; 16] = core::array::from_fn(|i| i as u8);
            let plaintext: [u8; SIZE] = core::array::from_fn(|i| 0xff - i as u8);
            let expected = unhex($ciphertext);
            let reference = <$reference>::new_with_tweak(&key, &tweak);
            let mut words: [u64; $words] = core::array::from_fn(|i| {
                u64::from_le_bytes(plaintext[i * 8..i * 8 + 8].try_into().unwrap())
            });
            reference.encrypt_block_u64(&mut words);
            let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            assert_eq!(bytes, expected);
            reference.decrypt_block_u64(&mut words);
            let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            assert_eq!(bytes, plaintext);

            let mut seed = 0x9e37_79b9_7f4a_7c15u64;
            let mut next = || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            };
            for _ in 0..64 {
                let key: [u8; SIZE] = core::array::from_fn(|_| next());
                let tweak: [u8; 16] = core::array::from_fn(|_| next());
                let input: [u8; SIZE] = core::array::from_fn(|_| next());
                let reference = <$reference>::new_with_tweak(&key, &tweak);
                for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                    let mut words: [u64; $words] = core::array::from_fn(|i| {
                        u64::from_le_bytes(input[i * 8..i * 8 + 8].try_into().unwrap())
                    });
                    match direction {
                        CipherDirection::Encrypt => reference.encrypt_block_u64(&mut words),
                        CipherDirection::Decrypt => reference.decrypt_block_u64(&mut words),
                    }
                    let expected: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
                    let mut engine = ThreefishEngine::<$words>::new();
                    engine
                        .init(direction, &Params::with_tweak(&key, &tweak))
                        .unwrap();
                    let mut actual = [0; SIZE];
                    engine.process_block(&input, &mut actual).unwrap();
                    assert_eq!(actual.as_slice(), expected);
                }
            }
        }
    };
}

compare!(
    threefish_256_matches_a_nonzero_tweak_kat_and_64_random_pairs,
    Threefish256,
    4,
    "e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df"
);

compare!(
    threefish_512_matches_a_nonzero_tweak_kat_and_64_random_pairs,
    Threefish512,
    8,
    "e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779\
         272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d"
);

compare!(
    threefish_1024_matches_a_nonzero_tweak_kat_and_64_random_pairs,
    Threefish1024,
    16,
    "a6654ddbd73cc3b05dd777105aa849bce49372eaaffc5568d254771bab85531c\
         94f780e7ffaae430d5d8af8c70eebbe1760f3b42b737a89cb363490d670314bd\
         8aa41ee63c2e1f45fbd477922f8360b388d6125ea6c7af0ad7056d01796e90c8\
         3313f4150a5716b30ed5f569288ae974ce2b4347926fce57de44512177dd7cde"
);
