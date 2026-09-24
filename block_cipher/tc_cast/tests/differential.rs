//! CAST5 and CAST6 agree with RustCrypto at every accepted key length.

mod common;

mod cast5_comparison {
    use super::common::unhex;
    use cast5::Cast5;
    use cast5::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
    use tc_cast_v2::{Cast5Engine, cast5::*};

    #[test]
    fn cast5_matches_rustcrypto_on_the_known_vector_and_64_key_block_pairs() {
        let key = unhex("0123456712345678234567893456789A");
        let plaintext = unhex("0123456789ABCDEF");
        let ciphertext = unhex("238B4FE5847E44B2");
        let reference = Cast5::new_from_slice(&key).unwrap();
        let mut block = Block::<Cast5>::try_from(plaintext.as_slice()).unwrap();
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
                let reference = Cast5::new_from_slice(&key).unwrap();
                for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                    let mut expected = Block::<Cast5>::from(input);
                    match direction {
                        CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                        CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                    }
                    let mut engine = Cast5Engine::new();
                    engine.init(direction, &KeyRef::new(&key)).unwrap();
                    let mut actual = [0; BLOCK_BYTES];
                    engine.process_block(&input, &mut actual).unwrap();
                    assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
                }
            }
        }
    }
}
mod cast6_comparison {
    use super::common::unhex;
    use cast6::Cast6;
    use cast6::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
    use tc_cast_v2::{Cast6Engine, cast6::*};

    #[test]
    fn cast6_matches_rustcrypto_on_the_known_vector_and_64_key_block_pairs() {
        let key = unhex("2342bb9efa38542c0af75647f29f615d");
        let plaintext = unhex("00000000000000000000000000000000");
        let ciphertext = unhex("c842a08972b43d20836c91d1b7530f6b");
        let reference = Cast6::new_from_slice(&key).unwrap();
        let mut block = Block::<Cast6>::try_from(plaintext.as_slice()).unwrap();
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
                let reference = Cast6::new_from_slice(&key).unwrap();
                for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                    let mut expected = Block::<Cast6>::from(input);
                    match direction {
                        CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                        CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                    }
                    let mut engine = Cast6Engine::new();
                    engine.init(direction, &KeyRef::new(&key)).unwrap();
                    let mut actual = [0; BLOCK_BYTES];
                    engine.process_block(&input, &mut actual).unwrap();
                    assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
                }
            }
        }
    }
}
