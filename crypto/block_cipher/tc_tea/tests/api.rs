use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_params::KeyRef;
use tc_tea::{BLOCK_BYTES, KEY_BYTES, TeaEngine, XteaEngine};

#[test]
fn writes_algorithm_names() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &TeaEngine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "TEA");

    name.clear();
    let algorithm: &dyn AlgorithmName = &XteaEngine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "XTEA");
}

#[test]
fn both_engines_validate_state_key_length_and_buffers() {
    let mut tea = TeaEngine::new();
    let mut xtea = XteaEngine::new();
    assert_eq!(tea.block_size(), BLOCK_BYTES);
    assert_eq!(xtea.block_size(), BLOCK_BYTES);
    assert_eq!(
        tea.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );
    assert_eq!(
        xtea.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

    for length in [0, KEY_BYTES - 1, KEY_BYTES + 1, 24, 32] {
        let key = vec![0u8; length];
        assert_eq!(
            tea.init(CipherDirection::Encrypt, &KeyRef::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
        assert_eq!(
            xtea.init(CipherDirection::Encrypt, &KeyRef::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }

    tea.init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; KEY_BYTES]))
        .unwrap();
    assert_eq!(
        tea.process_block(&[0u8; BLOCK_BYTES - 1], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::BufferTooShort)
    );
    assert_eq!(
        tea.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES - 1]),
        Err(BlockError::BufferTooShort)
    );
}

#[test]
fn initialized_engines_support_dynamic_dispatch() {
    let mut tea = TeaEngine::new();
    tea.init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; KEY_BYTES]))
        .unwrap();
    let mut xtea = XteaEngine::new();
    xtea.init(CipherDirection::Encrypt, &KeyRef::new(&[0u8; KEY_BYTES]))
        .unwrap();

    let ciphers: [Box<dyn BlockCipher>; 2] = [Box::new(tea), Box::new(xtea)];
    for cipher in &ciphers {
        assert_eq!(cipher.block_size(), BLOCK_BYTES);
    }
}
