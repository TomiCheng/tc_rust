use tc_aria::{ALGO_NAME, AriaEngine, BLOCK_BYTES, KEY_BYTES};
use tc_block_cipher::{
    BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError, KeyRef,
};

#[test]
fn the_algorithm_name_does_not_depend_on_initialization_key_size_or_direction() {
    let mut engine = AriaEngine::new();
    assert_eq!(engine.to_string(), ALGO_NAME);
    for length in KEY_BYTES {
        for direction in [CipherDirection::Encrypt, CipherDirection::Decrypt] {
            engine
                .init(direction, &KeyRef::new(&[0x11; 32][..length]))
                .unwrap();
            assert_eq!(engine.to_string(), "ARIA");
        }
    }
}

#[test]
fn processing_requires_initialization_valid_key_lengths_and_full_block_buffers() {
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
fn an_initialized_engine_can_be_used_through_the_block_cipher_trait_object() {
    let mut engine = AriaEngine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 16]))
        .unwrap();

    let cipher: Box<dyn BlockCipher<Error = BlockError>> = Box::new(engine);
    assert_eq!(cipher.block_size(), BLOCK_BYTES);
}
