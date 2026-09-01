use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_idea::{BLOCK_BYTES, IdeaEngine, KEY_BYTES};
use tc_params::KeyRef;

#[test]
fn writes_algorithm_name() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &IdeaEngine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "IDEA");
}

#[test]
fn validates_state_key_length_and_buffers() {
    let mut engine = IdeaEngine::new();
    assert_eq!(engine.block_size(), BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

    for length in [0, KEY_BYTES - 1, KEY_BYTES + 1, 24] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }

    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; KEY_BYTES]))
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
    let mut engine = IdeaEngine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; KEY_BYTES]))
        .unwrap();

    let cipher: Box<dyn BlockCipher> = Box::new(engine);
    assert_eq!(cipher.block_size(), BLOCK_BYTES);
}
