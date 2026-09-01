use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::{KeyParams, Rc5Params};
use tc_rc5::{
    MAX_KEY_BYTES, MAX_ROUNDS, Params, RC5_32_BLOCK_BYTES, RC5_64_BLOCK_BYTES, Rc532Engine,
    Rc564Engine,
};

#[test]
fn writes_algorithm_names() {
    for (engine, expected) in [
        (&Rc532Engine::new() as &dyn AlgorithmName, "RC5-32"),
        (&Rc564Engine::new() as &dyn AlgorithmName, "RC5-64"),
    ] {
        let mut name = String::new();
        engine.write_algo_name(&mut name).unwrap();
        assert_eq!(name, expected);
    }
}

#[test]
fn accepts_custom_parameter_implementations() {
    struct Custom<'a> {
        key: &'a [u8],
        rounds: usize,
    }

    impl KeyParams for Custom<'_> {
        fn key(&self) -> &[u8] {
            self.key
        }
    }

    impl Rc5Params for Custom<'_> {
        fn rounds(&self) -> usize {
            self.rounds
        }
    }

    let params = Custom {
        key: &[0u8; 16],
        rounds: 16,
    };
    assert!(
        Rc532Engine::new()
            .init(CipherDirection::Encrypt, &params)
            .is_ok()
    );
    assert!(
        Rc564Engine::new()
            .init(CipherDirection::Encrypt, &params)
            .is_ok()
    );
}

#[test]
fn accepts_maximum_key_length_and_round_count() {
    let key = [0xa5; MAX_KEY_BYTES];
    let params = Params::new(&key, MAX_ROUNDS);

    let mut engine = Rc532Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();
    let plaintext = [0x5a; RC5_32_BLOCK_BYTES];
    let mut ciphertext = [0u8; RC5_32_BLOCK_BYTES];
    engine.process_block(&plaintext, &mut ciphertext).unwrap();

    engine.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0u8; RC5_32_BLOCK_BYTES];
    engine.process_block(&ciphertext, &mut recovered).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn validates_state_parameters_and_buffers() {
    let mut engine = Rc532Engine::new();
    assert_eq!(engine.block_size(), RC5_32_BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; RC5_32_BLOCK_BYTES], &mut [0u8; RC5_32_BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

    for length in [0, MAX_KEY_BYTES + 1] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &Params::new(&key, 12)),
            Err(InitError::InvalidKeyLength(length))
        );
    }
    assert_eq!(
        engine.init(
            CipherDirection::Encrypt,
            &Params::new(&[0u8; 16], MAX_ROUNDS + 1)
        ),
        Err(InitError::InvalidRounds(MAX_ROUNDS + 1))
    );

    engine
        .init(
            CipherDirection::Encrypt,
            &Params::with_default_rounds(&[0u8; 16]),
        )
        .unwrap();
    assert_eq!(
        engine.process_block(
            &[0u8; RC5_32_BLOCK_BYTES - 1],
            &mut [0u8; RC5_32_BLOCK_BYTES]
        ),
        Err(BlockError::BufferTooShort)
    );
    assert_eq!(
        engine.process_block(
            &[0u8; RC5_32_BLOCK_BYTES],
            &mut [0u8; RC5_32_BLOCK_BYTES - 1]
        ),
        Err(BlockError::BufferTooShort)
    );

    assert_eq!(Rc564Engine::new().block_size(), RC5_64_BLOCK_BYTES);
}

#[test]
fn initialized_engines_support_dynamic_dispatch() {
    let params = Params::with_default_rounds(&[0u8; 16]);
    let mut engine = Rc532Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    let mut cipher: Box<dyn BlockCipher> = Box::new(engine);
    let mut output = [0u8; RC5_32_BLOCK_BYTES];
    assert_eq!(
        cipher.process_block(&[0u8; RC5_32_BLOCK_BYTES], &mut output),
        Ok(RC5_32_BLOCK_BYTES)
    );
}
