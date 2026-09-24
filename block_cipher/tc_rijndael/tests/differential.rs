//! Rijndael with a 128-bit block agrees with AES at its three key sizes.

mod common;

mod aes_128_comparison {
    use super::common::unhex;
    use aes::Aes128;
    use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
    use tc_rijndael_v2::Rijndael128Engine;

    #[test]
    fn rijndael_matches_aes_128_on_the_known_vector_and_64_key_block_pairs() {
        let key = unhex("80000000000000000000000000000000");
        let plaintext = unhex("00000000000000000000000000000000");
        let ciphertext = unhex("0edd33d3c621e546455bd8ba1418bec8");
        let reference = Aes128::new_from_slice(&key).unwrap();
        let mut block = Block::<Aes128>::try_from(plaintext.as_slice()).unwrap();
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
            let key: [u8; 16] = core::array::from_fn(|_| next());
            let input: [u8; 16] = core::array::from_fn(|_| next());
            let reference = Aes128::new_from_slice(&key).unwrap();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<Aes128>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = Rijndael128Engine::new();
                engine.init(direction, &KeyRef::new(&key)).unwrap();
                let mut actual = [0; 16];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
            }
        }
    }
}
mod aes_192_comparison {
    use super::common::unhex;
    use aes::Aes192;
    use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
    use tc_rijndael_v2::Rijndael128Engine;

    #[test]
    fn rijndael_matches_aes_192_on_the_known_vector_and_64_key_block_pairs() {
        let key = unhex("000000000000000000000000000000000000000000000000");
        let plaintext = unhex("80000000000000000000000000000000");
        let ciphertext = unhex("6cd02513e8d4dc986b4afe087a60bd0c");
        let reference = Aes192::new_from_slice(&key).unwrap();
        let mut block = Block::<Aes192>::try_from(plaintext.as_slice()).unwrap();
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
            let key: [u8; 24] = core::array::from_fn(|_| next());
            let input: [u8; 16] = core::array::from_fn(|_| next());
            let reference = Aes192::new_from_slice(&key).unwrap();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<Aes192>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = Rijndael128Engine::new();
                engine.init(direction, &KeyRef::new(&key)).unwrap();
                let mut actual = [0; 16];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
            }
        }
    }
}
mod aes_256_comparison {
    use super::common::unhex;
    use aes::Aes256;
    use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
    use tc_rijndael_v2::Rijndael128Engine;

    #[test]
    fn rijndael_matches_aes_256_on_the_known_vector_and_64_key_block_pairs() {
        let key = unhex("0000000000000000000000000000000000000000000000000000000000000000");
        let plaintext = unhex("80000000000000000000000000000000");
        let ciphertext = unhex("ddc6bf790c15760d8d9aeb6f9a75fd4e");
        let reference = Aes256::new_from_slice(&key).unwrap();
        let mut block = Block::<Aes256>::try_from(plaintext.as_slice()).unwrap();
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
            let key: [u8; 32] = core::array::from_fn(|_| next());
            let input: [u8; 16] = core::array::from_fn(|_| next());
            let reference = Aes256::new_from_slice(&key).unwrap();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<Aes256>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = Rijndael128Engine::new();
                engine.init(direction, &KeyRef::new(&key)).unwrap();
                let mut actual = [0; 16];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
            }
        }
    }
}
