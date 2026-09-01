use tc_cast::{Cast5Engine, Cast6Engine, cast5, cast6};
use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyRef;

#[test]
fn writes_algorithm_names() {
    for (algorithm, expected) in [
        (&Cast5Engine::new() as &dyn AlgorithmName, "CAST5"),
        (&Cast6Engine::new() as &dyn AlgorithmName, "CAST6"),
    ] {
        let mut name = String::new();
        algorithm.write_algo_name(&mut name).unwrap();
        assert_eq!(name, expected);
    }
}

#[test]
fn cast5_validates_state_key_lengths_and_buffers() {
    let mut engine = Cast5Engine::new();
    assert_eq!(engine.block_size(), cast5::BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; cast5::BLOCK_BYTES], &mut [0u8; cast5::BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

    for length in [0, cast5::MIN_KEY_BYTES - 1, cast5::MAX_KEY_BYTES + 1] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }

    engine
        .init(
            CipherDirection::Encrypt,
            &KeyRef::new(&[0u8; cast5::MIN_KEY_BYTES]),
        )
        .unwrap();
    assert_eq!(
        engine.process_block(
            &[0u8; cast5::BLOCK_BYTES - 1],
            &mut [0u8; cast5::BLOCK_BYTES]
        ),
        Err(BlockError::BufferTooShort)
    );
    assert_eq!(
        engine.process_block(
            &[0u8; cast5::BLOCK_BYTES],
            &mut [0u8; cast5::BLOCK_BYTES - 1]
        ),
        Err(BlockError::BufferTooShort)
    );
}

#[test]
fn cast6_validates_key_lengths() {
    let mut engine = Cast6Engine::new();
    assert_eq!(engine.block_size(), cast6::BLOCK_BYTES);
    for length in [0, 15, 17, 19, 21, 27, 29, 31, 33] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }
}

#[test]
fn initialized_engines_support_dynamic_dispatch() {
    let mut cast5 = Cast5Engine::new();
    cast5
        .init(
            CipherDirection::Encrypt,
            &KeyRef::new(&[0u8; cast5::MIN_KEY_BYTES]),
        )
        .unwrap();
    let mut cast6 = Cast6Engine::new();
    cast6
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 16]))
        .unwrap();

    let ciphers: [Box<dyn BlockCipher>; 2] = [Box::new(cast5), Box::new(cast6)];
    assert_eq!(ciphers[0].block_size(), 8);
    assert_eq!(ciphers[1].block_size(), 16);
}
