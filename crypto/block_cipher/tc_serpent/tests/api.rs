use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyRef;
use tc_serpent::{
    BLOCK_BYTES, KEY_STEP_BYTES, MAX_KEY_BYTES, MIN_KEY_BYTES, SerpentEngine, TnepresEngine,
};

#[test]
fn writes_algorithm_names() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &SerpentEngine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "Serpent");

    name.clear();
    let algorithm: &dyn AlgorithmName = &TnepresEngine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "Tnepres");
}

#[test]
fn accepts_every_four_byte_step_from_four_to_thirty_two() {
    for length in (MIN_KEY_BYTES..=MAX_KEY_BYTES).step_by(KEY_STEP_BYTES) {
        let key = vec![0u8; length];
        assert!(
            SerpentEngine::new()
                .init(CipherDirection::Encrypt, &KeyRef::new(&key))
                .is_ok(),
            "length {length}"
        );
        assert!(
            TnepresEngine::new()
                .init(CipherDirection::Encrypt, &KeyRef::new(&key))
                .is_ok(),
            "length {length}"
        );
    }
}

#[test]
fn rejects_out_of_range_and_unaligned_key_lengths() {
    let mut engine = SerpentEngine::new();
    for length in [0, 1, 3, 5, 15, 31, 33, 36] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }
}

#[test]
fn validates_state_and_buffers() {
    let mut engine = SerpentEngine::new();
    assert_eq!(engine.block_size(), BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

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

    let mut engine = TnepresEngine::new();
    assert_eq!(engine.block_size(), BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );
}

#[test]
fn initialized_engines_support_dynamic_dispatch() {
    let mut serpent = SerpentEngine::new();
    serpent
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 16]))
        .unwrap();
    let mut tnepres = TnepresEngine::new();
    tnepres
        .init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; 16]))
        .unwrap();

    let ciphers: [Box<dyn BlockCipher<Error = BlockError>>; 2] =
        [Box::new(serpent), Box::new(tnepres)];
    for cipher in &ciphers {
        assert_eq!(cipher.block_size(), BLOCK_BYTES);
    }
}
