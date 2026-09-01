use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyRef;
use tc_rijndael::{
    KEY_BYTES, Rijndael128Engine, Rijndael160Engine, Rijndael192Engine, Rijndael224Engine,
    Rijndael256Engine, RijndaelEngine,
};

#[test]
fn writes_algorithm_name() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &Rijndael128Engine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "Rijndael");
}

#[test]
fn variants_report_their_block_sizes() {
    assert_eq!(Rijndael128Engine::new().block_size(), 16);
    assert_eq!(Rijndael160Engine::new().block_size(), 20);
    assert_eq!(Rijndael192Engine::new().block_size(), 24);
    assert_eq!(Rijndael224Engine::new().block_size(), 28);
    assert_eq!(Rijndael256Engine::new().block_size(), 32);
}

fn accepts_all_keys<const BLOCK_COLUMNS: usize>() {
    for length in KEY_BYTES {
        let key = vec![0u8; length];
        assert!(
            RijndaelEngine::<BLOCK_COLUMNS>::new()
                .init(CipherDirection::Encrypt, &KeyRef::new(&key))
                .is_ok(),
            "block {} bits, key {length} bytes",
            BLOCK_COLUMNS * 32,
        );
    }
}

#[test]
fn every_block_size_accepts_every_key_size() {
    accepts_all_keys::<4>();
    accepts_all_keys::<5>();
    accepts_all_keys::<6>();
    accepts_all_keys::<7>();
    accepts_all_keys::<8>();
}

#[test]
fn validates_state_key_length_and_buffers() {
    let mut engine = Rijndael160Engine::new();
    assert_eq!(
        engine.process_block(&[0u8; 20], &mut [0u8; 20]),
        Err(BlockError::NotInitialised)
    );

    for length in [0, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 64] {
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
        engine.process_block(&[0u8; 19], &mut [0u8; 20]),
        Err(BlockError::BufferTooShort)
    );
    assert_eq!(
        engine.process_block(&[0u8; 20], &mut [0u8; 19]),
        Err(BlockError::BufferTooShort)
    );
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let mut engine = Rijndael256Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 20]))
        .unwrap();

    let mut cipher: Box<dyn BlockCipher> = Box::new(engine);
    let mut output = [0u8; 32];
    assert_eq!(cipher.process_block(&[0u8; 32], &mut output), Ok(32));
}
