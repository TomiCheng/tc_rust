use tc_aria::{AriaEngine, BLOCK_BYTES};
use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyRef;

#[test]
fn writes_algorithm_name() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &AriaEngine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "ARIA");
}

#[test]
fn validates_state_key_lengths_and_buffers() {
    let mut engine = AriaEngine::new();
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
fn initialized_engine_supports_dynamic_dispatch() {
    let mut engine = AriaEngine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 16]))
        .unwrap();

    let cipher: Box<dyn BlockCipher<Error = BlockError>> = Box::new(engine);
    assert_eq!(cipher.block_size(), BLOCK_BYTES);
}
