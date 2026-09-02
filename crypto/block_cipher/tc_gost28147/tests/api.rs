use tc_cipher::{BlockCipher, BlockCipherInit, BlockError, CipherDirection, InitError};
use tc_crypto::AlgorithmName;
use tc_gost28147::{BLOCK_BYTES, Gost28147Engine, KEY_BYTES, KeyWithSBox, s_box};

#[test]
fn writes_algorithm_name() {
    let mut name = String::new();
    let algorithm: &dyn AlgorithmName = &Gost28147Engine::new();
    algorithm.write_algo_name(&mut name).unwrap();
    assert_eq!(name, "Gost28147");
}

#[test]
fn validates_state_key_length_and_buffers() {
    let mut engine = Gost28147Engine::new();
    assert_eq!(engine.block_size(), BLOCK_BYTES);
    assert_eq!(
        engine.process_block(&[0u8; BLOCK_BYTES], &mut [0u8; BLOCK_BYTES]),
        Err(BlockError::NotInitialised)
    );

    for length in [0, KEY_BYTES - 1, KEY_BYTES + 1, 16, 24] {
        let key = vec![0u8; length];
        assert_eq!(
            engine.init(CipherDirection::Encrypt, &KeyWithSBox::new(&key)),
            Err(InitError::InvalidKeyLength(length))
        );
    }

    engine
        .init(
            CipherDirection::Encrypt,
            &KeyWithSBox::new(&[0u8; KEY_BYTES]),
        )
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

/// The engine checks the table's length but not its contents, matching Bouncy
/// Castle. A table that is the right size is accepted whatever it holds.
#[test]
fn validates_the_s_box_length_only() {
    let key = [0u8; KEY_BYTES];
    let mut engine = Gost28147Engine::new();

    for length in [0, s_box::BYTES - 1, s_box::BYTES + 1, 64, 256] {
        let table = vec![0u8; length];
        assert_eq!(
            engine.init(
                CipherDirection::Encrypt,
                &KeyWithSBox::with_s_box(&key, &table)
            ),
            Err(InitError::InvalidSBoxLength(length))
        );
    }

    // 全零的表不是合法的 S-box,但長度正確,所以照收。
    let degenerate = [0u8; s_box::BYTES];
    assert!(
        engine
            .init(
                CipherDirection::Encrypt,
                &KeyWithSBox::with_s_box(&key, &degenerate)
            )
            .is_ok()
    );
}

#[test]
fn every_standard_table_is_accepted() {
    let key = [0u8; KEY_BYTES];
    for table in [
        s_box::DEFAULT,
        s_box::D_TEST,
        s_box::E_TEST,
        s_box::E_A,
        s_box::E_B,
        s_box::E_C,
        s_box::E_D,
        s_box::D_A,
    ] {
        assert!(
            Gost28147Engine::new()
                .init(
                    CipherDirection::Encrypt,
                    &KeyWithSBox::with_s_box(&key, &table)
                )
                .is_ok()
        );
    }
}

#[test]
fn initialized_engine_supports_dynamic_dispatch() {
    let mut engine = Gost28147Engine::new();
    engine
        .init(
            CipherDirection::Encrypt,
            &KeyWithSBox::new(&[0u8; KEY_BYTES]),
        )
        .unwrap();

    let cipher: Box<dyn BlockCipher<Error = BlockError>> = Box::new(engine);
    assert_eq!(cipher.block_size(), BLOCK_BYTES);
}
