use tc_camellia::{BLOCK_BYTES, CamelliaEngine, CamelliaLightEngine};
use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyRef;

#[test]
fn writes_algorithm_names() {
    for algorithm in [
        &CamelliaEngine::new() as &dyn AlgorithmName,
        &CamelliaLightEngine::new() as &dyn AlgorithmName,
    ] {
        let mut name = String::new();
        algorithm.write_algo_name(&mut name).unwrap();
        assert_eq!(name, "Camellia");
    }
}

#[test]
fn validates_state_key_lengths_and_buffers() {
    let mut engine = CamelliaEngine::new();
    assert_eq!(engine.block_size(), BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

    for length in [0, 15, 17, 23, 25, 31, 33] {
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
}

#[test]
fn light_engine_validates_key_lengths() {
    let mut engine = CamelliaLightEngine::new();
    assert_eq!(
        engine.init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 15])),
        Err(InitError::InvalidKeyLength(15))
    );
}

#[test]
fn initialized_engines_support_dynamic_dispatch() {
    let params = KeyRef::new(&[0u8; 16]);
    let mut standard = CamelliaEngine::new();
    standard.init(CipherDirection::Encrypt, &params).unwrap();
    let mut light = CamelliaLightEngine::new();
    light.init(CipherDirection::Encrypt, &params).unwrap();

    let ciphers: [Box<dyn BlockCipher>; 2] = [Box::new(standard), Box::new(light)];
    assert!(
        ciphers
            .iter()
            .all(|cipher| cipher.block_size() == BLOCK_BYTES)
    );
}
