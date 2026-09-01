mod common;

use common::Key;
use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_des::{BLOCK_BYTES, DesEdeEngine, DesEngine};

#[test]
fn algorithm_names_are_written_without_allocation_by_the_engines() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &DesEngine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "DES");

    name.clear();
    let algorithm: &dyn AlgorithmName = &DesEdeEngine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "DESede");
}

#[test]
fn des_validates_state_key_and_buffers() {
    let mut engine = DesEngine::new();
    assert_eq!(engine.block_size(), BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

    for key in [&[0u8; 7][..], &[0u8; 9][..]] {
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &Key(key)),
            Err(InitError::InvalidKeyLength(key.len()))
        );
    }

    engine
        .init(CipherDirection::Encrypt, &Key(&[0u8; 8]))
        .unwrap();
    assert_eq!(
        engine.process_block(&[0u8; 7], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::BufferTooShort)
    );
    assert_eq!(
        engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; 7]),
        Err(BlockError::BufferTooShort)
    );
}

#[test]
fn triple_des_accepts_only_two_or_three_component_keys() {
    let mut engine = DesEdeEngine::new();
    for length in [0, 8, 15, 17, 23, 25] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &Key(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }

    assert!(
        engine
            .init(CipherDirection::Encrypt, &Key(&[0u8; 16]))
            .is_ok()
    );
    assert!(
        engine
            .init(CipherDirection::Encrypt, &Key(&[0u8; 24]))
            .is_ok()
    );
}
