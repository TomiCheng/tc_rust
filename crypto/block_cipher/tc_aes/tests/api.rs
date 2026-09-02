use tc_aes::{AesEngine, AesLightEngine, BLOCK_BYTES, KEY_BYTES};
use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyRef;

/// Both engines implement the same cipher, so both report the same name.
#[test]
fn writes_algorithm_name() {
    let mut name = String::new();
    for algorithm in [
        &AesEngine::new() as &dyn AlgorithmName,
        &AesLightEngine::new() as &dyn AlgorithmName,
    ] {
        name.clear();
        algorithm.write_algo_name(&mut name).unwrap();
        assert_eq!(name, "AES");
    }
}

macro_rules! check_engine {
    ($engine:ty) => {{
        let mut engine = <$engine>::new();
        assert_eq!(engine.block_size(), BLOCK_BYTES);
        assert_eq!(
            engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
            Err(BlockError::NotInitialised)
        );

        for length in KEY_BYTES {
            let key = vec![0u8; length];
            assert!(
                engine
                    .init(CipherDirection::Encrypt, &KeyRef::new(&key))
                    .is_ok(),
                "length {length}"
            );
        }

        for length in [0, 8, 15, 17, 23, 25, 31, 33, 64] {
            let key = vec![0u8; length];
            assert_eq!(
                engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)),
                Err(InitError::InvalidKeyLength(length))
            );
        }

        engine
            .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 16]))
            .unwrap();
        assert_eq!(
            engine.process_block(&[0u8; BLOCK_BYTES - 1], &mut [0u8; BLOCK_BYTES]),
            Err(BlockError::BufferTooShort)
        );
        assert_eq!(
            engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES - 1]),
            Err(BlockError::BufferTooShort)
        );
    }};
}

#[test]
fn both_engines_validate_state_key_lengths_and_buffers() {
    check_engine!(AesEngine);
    check_engine!(AesLightEngine);
}

#[test]
fn initialized_engines_support_dynamic_dispatch() {
    let mut engine = AesEngine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 32]))
        .unwrap();
    let mut light = AesLightEngine::new();
    light
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 32]))
        .unwrap();

    let ciphers: [Box<dyn BlockCipher<Error = BlockError>>; 2] =
        [Box::new(engine), Box::new(light)];
    for cipher in &ciphers {
        assert_eq!(cipher.block_size(), BLOCK_BYTES);
    }
}
