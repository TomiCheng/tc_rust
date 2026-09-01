use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyRef;
use tc_twofish::{BLOCK_BYTES, KEY_BYTES, TwofishEngine};

#[test]
fn writes_algorithm_name() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &TwofishEngine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "Twofish");
}

#[test]
fn accepts_every_documented_key_length() {
    for length in KEY_BYTES {
        let key = vec![0u8; length];
        assert!(
            TwofishEngine::new()
                .init(CipherDirection::Encrypt, &KeyRef::new(&key))
                .is_ok(),
            "length {length}"
        );
    }
}

#[test]
fn validates_state_key_length_and_buffers() {
    let mut engine = TwofishEngine::new();
    assert_eq!(engine.block_size(), BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

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
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let mut engine = TwofishEngine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 32]))
        .unwrap();

    let cipher: Box<dyn BlockCipher> = Box::new(engine);
    assert_eq!(cipher.block_size(), BLOCK_BYTES);
}
