use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_dstu7624::{Engine128, Engine256, Engine512};
use tc_params::KeyRef;

#[test]
fn writes_algorithm_names() {
    for algorithm in [
        &Engine128::new() as &dyn AlgorithmName,
        &Engine256::new() as &dyn AlgorithmName,
        &Engine512::new() as &dyn AlgorithmName,
    ] {
        let mut name = String::new();
        algorithm.write_algo_name(&mut name).unwrap();
        assert_eq!(name, "DSTU7624");
    }
}

#[test]
fn reports_block_sizes_and_pre_init_error() {
    assert_eq!(Engine128::new().block_size(), 16);
    assert_eq!(Engine256::new().block_size(), 32);
    assert_eq!(Engine512::new().block_size(), 64);

    assert_eq!(
        Engine128::new().process_block(&[0u8; 16], &mut [0u8; 16]),
        Err(BlockError::NotInitialised)
    );
}

#[test]
fn validates_keys_for_each_block_size() {
    let mut engine128 = Engine128::new();
    for length in [16, 32] {
        engine128
            .init(CipherDirection::Encrypt, &KeyRef::new(&vec![0u8; length]))
            .unwrap();
    }
    assert_eq!(
        engine128.init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 64])),
        Err(InitError::InvalidKeyLength(64))
    );

    let mut engine256 = Engine256::new();
    for length in [32, 64] {
        engine256
            .init(CipherDirection::Encrypt, &KeyRef::new(&vec![0u8; length]))
            .unwrap();
    }
    assert_eq!(
        engine256.init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 16])),
        Err(InitError::InvalidKeyLength(16))
    );

    let mut engine512 = Engine512::new();
    engine512
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 64]))
        .unwrap();
    assert_eq!(
        engine512.init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 32])),
        Err(InitError::InvalidKeyLength(32))
    );
}

#[test]
fn rejects_short_buffers() {
    let mut engine = Engine128::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 16]))
        .unwrap();
    assert_eq!(
        engine.process_block(&[0u8; 15], &mut [0u8; 16]),
        Err(BlockError::BufferTooShort)
    );
    assert_eq!(
        engine.process_block(&[0u8; 16], &mut [0u8; 15]),
        Err(BlockError::BufferTooShort)
    );
}

#[test]
fn initialized_engines_support_dynamic_dispatch() {
    let mut engine128 = Engine128::new();
    engine128
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 16]))
        .unwrap();
    let mut engine256 = Engine256::new();
    engine256
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 32]))
        .unwrap();
    let mut engine512 = Engine512::new();
    engine512
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 64]))
        .unwrap();

    let ciphers: [Box<dyn BlockCipher>; 3] = [
        Box::new(engine128),
        Box::new(engine256),
        Box::new(engine512),
    ];
    assert_eq!(ciphers[0].block_size(), 16);
    assert_eq!(ciphers[1].block_size(), 32);
    assert_eq!(ciphers[2].block_size(), 64);
}
