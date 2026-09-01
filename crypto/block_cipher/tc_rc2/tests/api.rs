use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::{KeyParams, Rc2Params};
use tc_rc2::{BLOCK_BYTES, MAX_EFFECTIVE_KEY_BITS, MAX_KEY_BYTES, Params, Rc2Engine};

#[test]
fn writes_algorithm_name() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &Rc2Engine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "RC2");
}

#[test]
fn validates_state_key_length_and_buffers() {
    let mut engine = Rc2Engine::new();
    assert_eq!(engine.block_size(), BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

    for length in [0, MAX_KEY_BYTES + 1] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &Params::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }

    engine
        .init(CipherDirection::Encrypt, &Params::new(&[0u8; 8]))
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
fn validates_effective_key_size() {
    let key = [0u8; 8];
    let mut engine = Rc2Engine::new();

    for bits in [0, MAX_EFFECTIVE_KEY_BITS + 1] {
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &Params::with_effective_key_bits(&key, bits),
            ),
            Err(InitError::InvalidEffectiveKeyBits(bits))
        );
    }
}

struct ThirdPartyParams<'a> {
    key: &'a [u8],
    effective_key_bits: usize,
}

impl KeyParams for ThirdPartyParams<'_> {
    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Rc2Params for ThirdPartyParams<'_> {
    fn effective_key_bits(&self) -> usize {
        self.effective_key_bits
    }
}

#[test]
fn accepts_third_party_params_and_supports_dynamic_dispatch() {
    let params = ThirdPartyParams {
        key: &[0u8; 8],
        effective_key_bits: 63,
    };
    let mut engine = Rc2Engine::new();
    engine.init(CipherDirection::Encrypt, &params).unwrap();

    let mut cipher: Box<dyn BlockCipher> = Box::new(engine);
    let mut output = [0u8; BLOCK_BYTES];
    assert_eq!(
        cipher.process_block(&[0u8; BLOCK_BYTES], &mut output),
        Ok(BLOCK_BYTES)
    );
    assert_eq!(output, [0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff]);
}
