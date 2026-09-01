use tc_chacha::{
    ChaCha7539Engine, ChaChaEngine, DEFAULT_ROUNDS, IV_BYTES, KEY_BYTES, XChaCha20Engine,
    chacha7539, xchacha20,
};
use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::{KeyParams, KeyWithIvParams, KeyWithIvRef};

#[test]
fn writes_algorithm_names() {
    for (engine, expected) in [
        (ChaChaEngine::new(), "ChaCha20"),
        (ChaChaEngine::with_rounds(12).unwrap(), "ChaCha12"),
        (ChaChaEngine::with_rounds(8).unwrap(), "ChaCha8"),
    ] {
        let mut name = String::new();
        engine.write_algo_name(&mut name).unwrap();
        assert_eq!(name, expected);
    }

    for (engine, expected) in [
        (ChaCha7539Engine::new(), "ChaCha7539"),
        (ChaCha7539Engine::default(), "ChaCha7539"),
    ] {
        let mut name = String::new();
        engine.write_algo_name(&mut name).unwrap();
        assert_eq!(name, expected);
    }

    let mut name = String::new();
    XChaCha20Engine::new().write_algo_name(&mut name).unwrap();
    assert_eq!(name, "XChaCha20");
}

#[test]
fn validates_ietf_and_extended_parameters() {
    let mut ietf = ChaCha7539Engine::new();
    assert_eq!(ietf.return_byte(0), Err(StreamError::NotInitialised));
    assert_eq!(
        ietf.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; 16], &[0; chacha7539::IV_BYTES]),
        ),
        Err(InitError::InvalidKeyLength(16))
    );
    assert_eq!(
        ietf.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; chacha7539::KEY_BYTES], &[0; 11]),
        ),
        Err(InitError::InvalidIvLength(11))
    );

    let mut extended = XChaCha20Engine::new();
    assert_eq!(extended.return_byte(0), Err(StreamError::NotInitialised));
    assert_eq!(
        extended.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; 16], &[0; xchacha20::IV_BYTES]),
        ),
        Err(InitError::InvalidKeyLength(16))
    );
    assert_eq!(
        extended.init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; xchacha20::KEY_BYTES], &[0; 23]),
        ),
        Err(InitError::InvalidIvLength(23))
    );
}

#[test]
fn validates_round_count() {
    assert_eq!(
        ChaChaEngine::with_rounds(0).err(),
        Some(InitError::InvalidRounds(0))
    );
    assert_eq!(
        ChaChaEngine::with_rounds(7).err(),
        Some(InitError::InvalidRounds(7))
    );
    assert_eq!(DEFAULT_ROUNDS, 20);
}

#[test]
fn accepts_custom_parameter_implementations() {
    struct Custom<'a> {
        key: &'a [u8],
        iv: &'a [u8],
    }

    impl KeyParams for Custom<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }

    impl KeyWithIvParams for Custom<'_> {
        fn iv(&self) -> &[u8] {
            self.iv
        }
    }

    assert!(
        ChaChaEngine::new()
            .init(
                CipherDirection::Encrypt,
                &Custom {
                    key: &[0; 32],
                    iv: &[0; IV_BYTES],
                },
            )
            .is_ok()
    );
}

#[test]
fn validates_state_parameters_and_output() {
    let mut engine = ChaChaEngine::new();
    assert_eq!(engine.return_byte(0), Err(StreamError::NotInitialised));
    assert_eq!(
        engine.process_bytes(&[0; 1], &mut [0; 1]),
        Err(StreamError::NotInitialised)
    );

    for length in [0, 15, 17, 31, 33] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &KeyWithIvRef::new(&key, &[0; IV_BYTES]),
            ),
            Err(InitError::InvalidKeyLength(length))
        );
    }
    for length in [0, IV_BYTES - 1, IV_BYTES + 1] {
        let iv = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&[0; 32], &iv),),
            Err(InitError::InvalidIvLength(length))
        );
    }

    engine
        .init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; 32], &[0; IV_BYTES]),
        )
        .unwrap();
    assert_eq!(
        engine.process_bytes(&[0; 2], &mut [0; 1]),
        Err(StreamError::BufferTooShort)
    );

    assert_eq!(KEY_BYTES, [16, 32]);
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let mut engine = ChaChaEngine::new();
    engine
        .init(
            CipherDirection::Encrypt,
            &KeyWithIvRef::new(&[0; 32], &[0; IV_BYTES]),
        )
        .unwrap();

    let mut cipher: Box<dyn StreamCipher<Error = StreamError>> = Box::new(engine);
    let mut output = [0u8; 64];
    assert_eq!(cipher.process_bytes(&[0u8; 64], &mut output), Ok(64));
}
