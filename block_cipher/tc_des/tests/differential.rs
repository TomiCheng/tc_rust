//! DES and both EDE key sizes agree with RustCrypto after checking known answers.

mod common;

mod des_comparison {
    use super::common::unhex;
    use des::Des;
    use des::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
    use tc_des_v2::{BLOCK_BYTES, DesEngine};

    #[test]
    fn des_matches_rustcrypto_on_the_known_vector_and_64_key_block_pairs() {
        let key = unhex("133457799BBCDFF1");
        let plaintext = unhex("0123456789ABCDEF");
        let ciphertext = unhex("85E813540F0AB405");
        let reference = Des::new_from_slice(&key).unwrap();
        let mut block = Block::<Des>::try_from(plaintext.as_slice()).unwrap();
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
            let key: [u8; 8] = core::array::from_fn(|_| next());
            let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
            let reference = Des::new_from_slice(&key).unwrap();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<Des>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = DesEngine::new();
                engine.init(direction, &KeyRef::new(&key)).unwrap();
                let mut actual = [0; BLOCK_BYTES];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
            }
        }
    }
}
mod tdesede2_comparison {
    use super::common::unhex;
    use des::TdesEde2;
    use des::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
    use tc_des_v2::{BLOCK_BYTES, DesEdeEngine};

    #[test]
    fn tdesede2_matches_rustcrypto_on_the_known_vector_and_64_key_block_pairs() {
        let key = unhex("0123456789abcdeffedcba9876543210");
        let plaintext = unhex("4e6f772069732074");
        let ciphertext = unhex("d80a0d8b2bae5e4e");
        let reference = TdesEde2::new_from_slice(&key).unwrap();
        let mut block = Block::<TdesEde2>::try_from(plaintext.as_slice()).unwrap();
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
            let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
            let reference = TdesEde2::new_from_slice(&key).unwrap();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<TdesEde2>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = DesEdeEngine::new();
                engine.init(direction, &KeyRef::new(&key)).unwrap();
                let mut actual = [0; BLOCK_BYTES];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
            }
        }
    }
}
mod tdesede3_comparison {
    use super::common::unhex;
    use des::TdesEde3;
    use des::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
    use tc_des_v2::{BLOCK_BYTES, DesEdeEngine};

    #[test]
    fn tdesede3_matches_rustcrypto_on_the_known_vector_and_64_key_block_pairs() {
        let key = unhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123");
        let plaintext = unhex("FEDCBA9876543210");
        let ciphertext = unhex("0737F6C53750D4A4");
        let reference = TdesEde3::new_from_slice(&key).unwrap();
        let mut block = Block::<TdesEde3>::try_from(plaintext.as_slice()).unwrap();
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
            let input: [u8; BLOCK_BYTES] = core::array::from_fn(|_| next());
            let reference = TdesEde3::new_from_slice(&key).unwrap();
            for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
                let mut expected = Block::<TdesEde3>::from(input);
                match direction {
                    CipherDirection::Encrypt => reference.encrypt_block(&mut expected),
                    CipherDirection::Decrypt => reference.decrypt_block(&mut expected),
                }
                let mut engine = DesEdeEngine::new();
                engine.init(direction, &KeyRef::new(&key)).unwrap();
                let mut actual = [0; BLOCK_BYTES];
                engine.process_block(&input, &mut actual).unwrap();
                assert_eq!(actual.as_slice(), expected.as_slice(), "{direction:?}");
            }
        }
    }
}
