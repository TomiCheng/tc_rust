use tc_cipher::{CipherDirection, InitError, StreamCipher, StreamCipherInit, StreamError};
use tc_crypto::AlgorithmName;
use tc_params::{KeyParams, KeyRef};
use tc_rc4::{MAX_KEY_BYTES, Rc4Engine};

#[test]
fn writes_algorithm_name() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &Rc4Engine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "RC4");
}

#[test]
fn accepts_custom_parameter_implementations() {
    struct Custom<'a>(&'a [u8]);

    impl KeyParams for Custom<'_> {
        fn key(&self) -> &[u8] {
            self.0
        }
    }

    assert!(
        Rc4Engine::new()
            .init(CipherDirection::Encrypt, &Custom(b"Key"))
            .is_ok()
    );
}

#[test]
fn validates_state_key_length_and_output() {
    let mut engine = Rc4Engine::new();
    assert_eq!(engine.return_byte(0), Err(StreamError::NotInitialised));
    assert_eq!(
        engine.process_bytes(&[0; 1], &mut [0; 1]),
        Err(StreamError::NotInitialised)
    );

    for length in [0, MAX_KEY_BYTES + 1] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }

    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(b"Key"))
        .unwrap();
    assert_eq!(
        engine.process_bytes(&[0; 2], &mut [0; 1]),
        Err(StreamError::BufferTooShort)
    );
}

#[test]
fn accepts_maximum_key_length() {
    let key = [0xa5; MAX_KEY_BYTES];
    assert!(
        Rc4Engine::new()
            .init(CipherDirection::Encrypt, &KeyRef::new(&key))
            .is_ok()
    );
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let mut engine = Rc4Engine::new();
    engine
        .init(CipherDirection::Encrypt, &KeyRef::new(b"Key"))
        .unwrap();

    let mut cipher: Box<dyn StreamCipher<Error = StreamError>> = Box::new(engine);
    let mut output = [0u8; 9];
    assert_eq!(cipher.process_bytes(b"Plaintext", &mut output), Ok(9));
    assert_eq!(
        output,
        [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
    );
}
