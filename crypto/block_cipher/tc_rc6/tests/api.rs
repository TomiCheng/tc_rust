use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyRef;
use tc_rc6::{BLOCK_BYTES, MAX_KEY_BYTES, Rc6Engine};

#[test]
fn writes_algorithm_name() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &Rc6Engine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "RC6");
}

#[test]
fn accepts_variable_key_lengths() {
    for length in [1, 16, 24, 32, MAX_KEY_BYTES] {
        let key = vec![0u8; length];
        assert!(
            Rc6Engine::new()
                .init(CipherDirection::Encrypt, &KeyRef::new(&key))
                .is_ok(),
            "length {length}"
        );
    }
}

#[test]
fn validates_state_key_length_and_buffers() {
    let mut engine = Rc6Engine::new();
    assert_eq!(engine.block_size(), BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

    for length in [0, MAX_KEY_BYTES + 1] {
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
    let mut engine = Rc6Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 16]))
        .unwrap();

    let mut cipher: Box<dyn BlockCipher<Error = BlockError>> = Box::new(engine);
    let mut output = [0u8; BLOCK_BYTES];
    assert_eq!(
        cipher.process_block(&[0u8; BLOCK_BYTES], &mut output),
        Ok(BLOCK_BYTES)
    );
}
